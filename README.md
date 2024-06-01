# OAI-eUPF

This readme provides guidelines for deploying OAI 5G Core with an eBPF-based User Plane Function (UPF).
### Step 1: Clone this repository
```bash
git clone https://github.com/wafi981/-k8s-oai-eupf.git ~/k8s-oai-eupf
cd ~/k8s-oai-eupf
```
### Step 2: Install make and deploy rke2 kubernetes cluster
```bash
sudo apt install make -y
make node-prep
```
### Step 3: After rke2 installation deploy oai-5g-core with oai-ran-simulator
```bash
make oai
```
This will deploy end-to-end 5g core on kubernetes

after deploying the core go inside the oai-traffic-server pod 
```bash
kubectl exec -it <oai-traffic-server pod name> bash
```
and run these commands inside the po
```bash
ip route change default via 169.254.1.1 dev eth0
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 12.1.1.0/24 -o eth0 -j SNAT --to-source <eth0 ip address>
```
### Check internet connectivity 
Go inside oai-nr-ue pod 
```bash
kubectl exec -it <oai-nr-ue pod name> bash
```
change the default route to access dns server
```bash
ip route change default via 169.254.1.1 dev eth0
```
and after doing this the internet works
```bash
ping -I 12.1.1.100 google.com
```
