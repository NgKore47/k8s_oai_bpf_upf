# Copyright 2018-present Open Networking Foundation
#
# SPDX-License-Identifier: Apache-2.0

SHELL		:= /bin/bash
MAKEDIR		:= $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD		?= $(MAKEDIR)/build
M           	?= $(BUILD)/milestones
SCRIPTDIR	:= $(MAKEDIR)/scripts
RESOURCEDIR	:= $(MAKEDIR)/resources
WORKSPACE	?= $(shell pwd)
VENV		?= $(BUILD)/venv/aiab

NS?=hexa
HELM_ARGS?=--create-namespace
HELM_ACTION?=install

4G_CORE_VALUES       ?= $(MAKEDIR)/sd-core-4g-values.yaml
5G_CORE_VALUES       ?= $(MAKEDIR)/sd-core-5g-values.yaml
5G_UPF_VALUES        ?= $(MAKEDIR)/upf-5g-values.yaml
OAISIM_VALUES        ?= $(MAKEDIR)/oaisim-values.yaml
ROC_VALUES           ?= $(MAKEDIR)/roc-values.yaml
ROC_DEFAULTENT_MODEL ?= $(MAKEDIR)/roc-defaultent-model.json
ROC_4G_MODELS        ?= $(MAKEDIR)/roc-4g-models.json
ROC_5G_MODELS        ?= $(MAKEDIR)/roc-5g-models.json
TEST_APP_VALUES      ?= $(MAKEDIR)/5g-test-apps-values.yaml
UPF_COUNT             = $(MAKEDIR)/upf-count.txt
GET_HELM              = get_helm.sh

KUBESPRAY_VERSION ?= release-2.17
DOCKER_VERSION    ?= '20.10'
HELM_VERSION	  ?= v3.10.3
KUBECTL_VERSION   ?= v1.23.15

RKE2_K8S_VERSION  ?= v1.25.15+rke2r2
K8S_VERSION       ?= v1.25.6
LPP_VERSION       ?= v0.0.24

OAISIM_UE_IMAGE ?= andybavier/lte-uesoftmodem:1.1.0-$(shell uname -r)
ENABLE_ROUTER ?= true
ENABLE_OAISIM ?= true
ENABLE_GNBSIM ?= false
ENABLE_SUBSCRIBER_PROXY ?= false
GNBSIM_COLORS ?= true

K8S_INSTALL ?= rke2
CTR_CMD     := sudo /var/lib/rancher/rke2/bin/ctr --address /run/k3s/containerd/containerd.sock --namespace k8s.io

PROXY_ENABLED   ?= false
HTTP_PROXY      ?= ${http_proxy}
HTTPS_PROXY     ?= ${https_proxy}
NO_PROXY        ?= ${no_proxy}

ONECLOUD	?= false

DATA_IFACE ?= data
ifeq ($(DATA_IFACE), data)
	RAN_SUBNET := 192.168.251.0/24
else
	RAN_SUBNET := $(shell ip route | grep $${DATA_IFACE} | awk '/kernel/ {print $$1}' | head -1)
	DATA_IFACE_PATH := $(shell find /*/systemd/network -maxdepth 1 -not -type d -name '*$(DATA_IFACE).network' -print)
	DATA_IFACE_CONF ?= $(shell basename $(DATA_IFACE_PATH)).d
endif

# systemd-networkd and systemd configs
LO_NETCONF            := /etc/systemd/network/20-aiab-lo.network
OAISIM_NETCONF        := $(LO_NETCONF) /etc/systemd/network/10-aiab-enb.netdev /etc/systemd/network/20-aiab-enb.network
ROUTER_POD_NETCONF    := /etc/systemd/network/10-aiab-dummy.netdev /etc/systemd/network/20-aiab-dummy.network
ROUTER_HOST_NETCONF   := /etc/systemd/network/10-aiab-access.netdev /etc/systemd/network/20-aiab-access.network /etc/systemd/network/10-aiab-core.netdev /etc/systemd/network/20-aiab-core.network /etc/systemd/network/$(DATA_IFACE_CONF)/macvlan.conf
UE_NAT_CONF           := /etc/systemd/system/aiab-ue-nat.service

# monitoring
RANCHER_MONITORING_CRD_CHART := rancher/rancher-monitoring-crd
RANCHER_MONITORING_CHART     := rancher/rancher-monitoring
MONITORING_VALUES            ?= $(MAKEDIR)/monitoring.yaml

NODE_IP ?= $(shell ip route get 8.8.8.8 | grep -oP 'src \K\S+')
ifndef NODE_IP
$(error NODE_IP is not set)
endif

MME_IP  ?=

HELM_GLOBAL_ARGS ?=

ifneq ("$(wildcard $(UPF_COUNT))","")
  UPF_NUMBER = $(shell cat $(UPF_COUNT))
else
  UPF_NUMBER = 0
endif

# Allow installing local charts or specific versions of published charts.
# E.g., to install the Aether 1.5 release:
#    CHARTS=release-1.5 make test
# Default is to install from the local charts.
# CHARTS     ?= local
# CONFIGFILE := configs/$(CHARTS)
# include $(CONFIGFILE)

cpu_family	:= $(shell lscpu | grep 'CPU family:' | awk '{print $$3}')
cpu_model	:= $(shell lscpu | grep 'Model:' | awk '{print $$2}')
os_vendor	:= $(shell lsb_release -i -s)
os_release	:= $(shell lsb_release -r -s)
USER		:= $(shell whoami)

.PHONY: node-prep clean oai-clean

$(M):
	mkdir -p $(M)

$(M)/system-check: | $(M)
	@if [[ $(cpu_family) -eq 6 ]]; then \
		if [[ $(cpu_model) -lt 60 ]]; then \
			echo "FATAL: haswell CPU or newer is required."; \
			exit 1; \
		fi \
	else \
		echo "FATAL: unsupported CPU family."; \
		exit 1; \
	fi
	@if [[ $(os_vendor) =~ (Ubuntu) ]]; then \
		if [[ ! $(os_release) =~ (18.04) ]]; then \
			echo "WARN: $(os_vendor) $(os_release) has not been tested."; \
		fi; \
		if dpkg --compare-versions 4.15 gt $(shell uname -r); then \
			echo "FATAL: kernel 4.15 or later is required."; \
			echo "Please upgrade your kernel by running" \
			"apt install --install-recommends linux-generic-hwe-$(os_release)"; \
			exit 1; \
		fi \
	else \
		echo "FAIL: unsupported OS."; \
		exit 1; \
	fi
	touch $@

$(M)/interface-check: | $(M)
ifeq ($(DATA_IFACE_CONF), .d)
	@echo
	@echo FATAL: Could not find systemd-networkd config for interface $(DATA_IFACE), exiting now!; exit 1
endif
	@echo "Add network configuration for enb interface"
	@if [[ "${ONECLOUD}" ==  "true" ]]; then \
		sudo cp netplan/01-enb-static-config.yaml /etc/netplan ; \
		sudo netplan apply ; \
		sleep 1 ; \
	fi
	touch $@

ifeq ($(K8S_INSTALL),kubespray)
$(M)/setup: | $(M) $(M)/interface-check
	sudo $(SCRIPTDIR)/cloudlab-disksetup.sh
	sudo apt update; sudo apt install -y software-properties-common python3 python3-pip python3-venv jq httpie ipvsadm
	touch $@
endif

ifeq ($(K8S_INSTALL),rke2)
$(M)/initial-setup: | $(M) $(M)/interface-check
	sudo $(SCRIPTDIR)/cloudlab-disksetup.sh
	sudo apt update; sudo apt install -y software-properties-common python3 python3-pip python3-venv jq httpie ipvsadm apparmor apparmor-utils
	systemctl list-units --full -all | grep "docker.service" || sudo apt install -y docker.io
	sudo adduser $(USER) docker || true
	touch $(M)/initial-setup

ifeq ($(PROXY_ENABLED),true)
$(M)/proxy-setting: | $(M)
	echo "Defaults env_keep += \"HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy\"" | sudo EDITOR='tee -a' visudo -f /etc/sudoers.d/proxy
	echo "HTTP_PROXY=$(HTTP_PROXY)" >> rke2-server
	echo "HTTPS_PROXY=$(HTTPS_PROXY)" >> rke2-server
	echo "NO_PROXY=$(NO_PROXY),.cluster.local,.svc,$(NODE_IP),192.168.84.0/24,192.168.85.0/24,$(RAN_SUBNET)" >> rke2-server
	sudo mv rke2-server /etc/default/
	echo "[Service]" >> http-proxy.conf
	echo "Environment='HTTP_PROXY=$(HTTP_PROXY)'" >> http-proxy.conf
	echo "Environment='HTTPS_PROXY=$(HTTPS_PROXY)'" >> http-proxy.conf
	echo "Environment='NO_PROXY=$(NO_PROXY)'" >> http-proxy.conf
	sudo mkdir -p /etc/systemd/system/docker.service.d
	sudo mv http-proxy.conf /etc/systemd/system/docker.service.d
	sudo systemctl daemon-reload
	sudo systemctl restart docker
	touch $(M)/proxy-setting
else
$(M)/proxy-setting: | $(M)
	@echo -n ""
	touch $(M)/proxy-setting
endif

$(M)/setup: | $(M)/initial-setup $(M)/proxy-setting
	touch $@
endif

$(BUILD)/kubespray: | $(M)/setup
	mkdir -p $(BUILD)
	cd $(BUILD); git clone https://github.com/kubernetes-incubator/kubespray.git -b $(KUBESPRAY_VERSION)

$(VENV)/bin/activate: | $(M)/setup
	python3 -m venv $(VENV)
	source "$(VENV)/bin/activate" && \
	python -m pip install -U pip && \
	deactivate

$(M)/kubespray-requirements: $(BUILD)/kubespray | $(VENV)/bin/activate
	source "$(VENV)/bin/activate" && \
	pip install -r $(BUILD)/kubespray/requirements.txt
	touch $@

ifeq ($(K8S_INSTALL),kubespray)
$(M)/k8s-ready: | $(M)/setup $(BUILD)/kubespray $(VENV)/bin/activate $(M)/kubespray-requirements
	source "$(VENV)/bin/activate" && cd $(BUILD)/kubespray; \
	ansible-playbook -b -i inventory/local/hosts.ini \
		-e "{'http_proxy' : $(HTTP_PROXY)}" \
		-e "{'https_proxy' : $(HTTPS_PROXY)}" \
		-e "{'no_proxy' : $(NO_PROXY)}" \
		-e "{'override_system_hostname' : False, 'disable_swap' : True}" \
		-e "{'docker_version' : $(DOCKER_VERSION)}" \
		-e "{'docker_iptables_enabled' : True}" \
		-e "{'kube_version' : $(K8S_VERSION)}" \
		-e "{'kube_network_plugin_multus' : True, 'multus_version' : stable, 'multus_cni_version' : 0.3.1}" \
		-e "{'kube_proxy_metrics_bind_address' : 0.0.0.0:10249}" \
		-e "{'kube_pods_subnet' : 192.168.84.0/24, 'kube_service_addresses' : 192.168.85.0/24}" \
		-e "{'kube_apiserver_node_port_range' : 2000-36767}" \
		-e "{'kubeadm_enabled': True}" \
		-e "{'kube_feature_gates' : [SCTPSupport=True]}" \
		-e "{'kubelet_custom_flags' : [--allowed-unsafe-sysctls=net.*, --node-ip=$(NODE_IP)]}" \
		-e "{'dns_min_replicas' : 1}" \
		-e "{'helm_enabled' : True, 'helm_version' : $(HELM_VERSION)}" \
		cluster.yml
	mkdir -p $(HOME)/.kube
	sudo cp -f /etc/kubernetes/admin.conf $(HOME)/.kube/config
	sudo chown $(shell id -u):$(shell id -g) $(HOME)/.kube/config
	kubectl wait pod -n kube-system --for=condition=Ready --all
	sudo adduser $(USER) docker
	touch $@

$(M)/helm-ready: | $(M)/k8s-ready
	# helm repo add incubator https://charts.helm.sh/incubator
	# helm repo add cord https://charts.opencord.org
	# helm repo add atomix https://charts.atomix.io
	# helm repo add onosproject https://charts.onosproject.org
	# helm repo add aether https://charts.aetherproject.org
	# helm repo add rancher http://charts.rancher.io/
	touch $@
endif

ifeq ($(K8S_INSTALL),rke2)
$(M)/k8s-ready: | $(M)/setup
	sudo mkdir -p /etc/rancher/rke2/
	[ -d /usr/local/etc/emulab ] && [ ! -e /var/lib/rancher ] && sudo ln -s /var/lib/rancher /mnt/extra/rancher || true  # that link gets deleted on cleanup
	echo "cni: multus,calico" >> config.yaml
	echo "cluster-cidr: 192.168.84.0/24" >> config.yaml
	echo "service-cidr: 192.168.85.0/24" >> config.yaml
	echo "kubelet-arg:" >> config.yaml
	echo "- --allowed-unsafe-sysctls="net.*"" >> config.yaml
	echo "- --node-ip="$(NODE_IP)"" >> config.yaml
	echo "pause-image: k8s.gcr.io/pause:3.3" >> config.yaml
	echo "kube-proxy-arg:" >> config.yaml
	echo "- --metrics-bind-address="0.0.0.0:10249"" >> config.yaml
	echo "- --proxy-mode="ipvs"" >> config.yaml
	echo "kube-apiserver-arg:" >> config.yaml
	echo "- --service-node-port-range="2000-36767"" >> config.yaml
	sudo mv config.yaml /etc/rancher/rke2/
	curl -sfL https://get.rke2.io | sudo INSTALL_RKE2_VERSION=$(RKE2_K8S_VERSION) sh -
	sudo systemctl enable rke2-server.service
	sudo systemctl start rke2-server.service
	sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml wait nodes --for=condition=Ready --all --timeout=300s
	sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml wait deployment -n kube-system --for=condition=available --all --timeout=300s
	@$(eval STORAGE_CLASS := $(shell /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get storageclass -o name))
	@echo "STORAGE_CLASS: ${STORAGE_CLASS}"
	if [ "$(STORAGE_CLASS)" == "" ]; then \
		sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/$(LPP_VERSION)/deploy/local-path-storage.yaml --wait=true; \
		sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'; \
	fi
	curl -LO "https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/linux/amd64/kubectl"
	sudo chmod +x kubectl
	sudo mv kubectl /usr/local/bin/
	kubectl version --client
	mkdir -p $(HOME)/.kube
	sudo cp /etc/rancher/rke2/rke2.yaml $(HOME)/.kube/config
	sudo chown -R $(shell id -u):$(shell id -g) $(HOME)/.kube
	touch $@
	kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/v0.72.0/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml

$(M)/helm-ready: | $(M)/k8s-ready
	curl -fsSL -o ${GET_HELM} https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
	chmod 700 ${GET_HELM}
	sudo DESIRED_VERSION=$(HELM_VERSION) ./${GET_HELM}
	helm repo add incubator https://charts.helm.sh/incubator
	helm repo add cord https://charts.opencord.org
	helm repo add atomix https://charts.atomix.io
	helm repo add onosproject https://charts.onosproject.org
	helm repo add aether https://charts.aetherproject.org
	helm repo add rancher http://charts.rancher.io/
	helm repo add hexaebpf https://kcl17.github.io/chars-test/helm/charts
	touch $@
endif

/opt/cni/bin/static: | $(M)/k8s-ready
	mkdir -p $(BUILD)/cni-plugins; cd $(BUILD)/cni-plugins; \
	wget https://github.com/containernetworking/plugins/releases/download/v0.8.2/cni-plugins-linux-amd64-v0.8.2.tgz && \
	tar xvfz cni-plugins-linux-amd64-v0.8.2.tgz
	sudo cp $(BUILD)/cni-plugins/static /opt/cni/bin/

node-prep: | $(M)/helm-ready /opt/cni/bin/static

oai-core: 
	sed -i "s/eth1/$(DATA_IFACE)/g" $(WORKSPACE)/oai-5g-core/oai-5g-basic/values.yaml
	sed -i "s/eth1/$(DATA_IFACE)/g" $(WORKSPACE)/oai-5g-ran/oai-gnb/values.yaml
	sed -i "s/eth1/$(DATA_IFACE)/g" $(WORKSPACE)/oai-5g-ran/oai-nr-ue/values.yaml
	@echo $(WORKSPACE)/oai-5g-ran/oai-nr-ue/values.yaml

	helm install basic $(WORKSPACE)/oai-5g-core/oai-5g-basic
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=basic --timeout=3m

oai-gnb:
	helm install gnb $(WORKSPACE)/oai-5g-ran/oai-gnb
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=oai-gnb --timeout=3m 

oai-ranue:
	helm install ranue $(WORKSPACE)/oai-5g-ran/oai-nr-ue
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=oai-nr-ue --timeout=3m 

oai : node-prep
ifeq ($(K8S_INSTALL),rke2)
oai: |  oai-core oai-gnb oai-ranue
endif


router-pod: | $(M)/router-pod
$(M)/router-pod: $(ROUTER_POD_NETCONF)
	sudo systemctl restart systemd-networkd
	DATA_IFACE=$(DATA_IFACE) envsubst < $(RESOURCEDIR)/router.yaml | kubectl apply -f -
	kubectl wait pod -n default --for=condition=Ready -l app=router --timeout=300s
	@touch $@

$(M)/router-host: $(ROUTER_HOST_NETCONF) $(UE_NAT_CONF)
	sudo systemctl daemon-reload
	sudo systemctl enable aiab-ue-nat.service
	sudo systemctl start aiab-ue-nat.service
	sudo systemctl restart systemd-networkd
	$(eval oiface := $(shell ip route list default | awk -F 'dev' '{ print $$2; exit }' | awk '{ print $$1 }'))
	@touch $@

router-clean:
	@kubectl delete net-attach-def router-net 2>/dev/null || true
	@kubectl delete po router 2>/dev/null || true
	kubectl wait --for=delete -l app=router pod --timeout=180s 2>/dev/null || true
	sudo ip link del access || true
	sudo ip link del core || true
	$(eval oiface := $(shell ip route list default | awk -F 'dev' '{ print $$2; exit }' | awk '{ print $$1 }'))
	sudo iptables -t nat -D POSTROUTING -s 172.250.0.0/16 -o $(oiface) -j MASQUERADE || true
	@sudo ip link del data 2>/dev/null || true
	@cd $(M); rm -f router-pod router-host

/etc/systemd/%:
	@sudo mkdir -p $(@D)
	@sed 's/DATA_IFACE/$(DATA_IFACE)/g' $(MAKEDIR)/systemd/$(@F) > /tmp/$(@F)
	@sudo cp /tmp/$(@F) $@
	echo "Installed $@"

clean-systemd:
	cd /etc/systemd/network && sudo rm -f 10-aiab* 20-aiab* */macvlan.conf
	cd /etc/systemd/system && sudo rm -f aiab*.service && sudo systemctl daemon-reload

oai-clean:
	helm uninstall basic gnb ranue

ifeq ($(K8S_INSTALL),rke2)
clean: | router-clean clean-systemd 
	sudo /usr/local/bin/rke2-uninstall.sh || true
	sudo rm -rf /usr/local/bin/kubectl
	rm -rf $(M)	
endif


