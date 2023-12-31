# K8s 未授权访问漏洞扫码器(K8sUnauthorizedAccessScanner)

## 支持的漏洞类型(Vulnerability Supported): 
+ 支持 Api Server 未授权访问漏洞检查(support scanning api server unauthorized access vulnerability)
+ 支持 Kubelet 未授权访问漏洞检查(support scanning kubelet unauthorized access vulnerability)
+ 支持 Etcd 未授权访问漏洞检查(support scanning etcd unauthorized access vulnerability)
+ 支持 Kube-Public Cluster-Info 未授权访问漏洞检查（(support scanning kube-public cluster-info unauthorized access vulnerability）
+ 支持 Dashboard 未授权访问漏洞检查(support scanning k8s dashboard unauthorized access vulnerability)
  + 该项仅支持显示响应报文头的 Content-Length 进而支持后续人工进行判断(Only support showing the content-length value in response packet header) 
+ 支持 docker remote 未授权访问漏洞检查(support scanning docker remote unauthorized access vulnerability)
+ 支持 docker registry 未授权访问漏洞检查(support scanning docker registry unauthorized access vulnerability)
 
## 用法(Usage): 
+ 参数(parameter):
  + -t   target to scan
  + -f   target file
  + -v   choose which vulnerability to scan: apiserver,kubelet,etcd,dashboard?
  + -c   thread count from 10 to 50 ,step 5, \[10, 15, 20, 25, 30, 35, 40, 45, 50\]
  
```bash
# Api Server
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v apiserver
python3 scanner.py -f apiserver_assests.txt -v apiserver -c 30

# Kubelet
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v kubelet
python3 scanner.py -f kubelet_assests.txt -v kubelet -c 30

# Etcd
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v etcd
python3 scanner.py -f etcd_assests.txt -v etcd -c 30

# Cluster
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v cluster
python3 scanner.py -f dashboard_assests.txt -v cluster -c 30

# Dashboard
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v dashboard
python3 scanner.py -f dashboard_assests.txt -v dashboard -c 30

# Remote
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v remote
python3 scanner.py -f docker_assests.txt -v remote -c 30

# Registry
python3 scanner.py -t http://xx.xx.xx.xx:port/ -v registry
python3 scanner.py -f docker_assests.txt -v registry -c 30
```
![截图20231129170546984](https://github.com/b0bac/k8sUnauthorizedAccessScanner/assets/11972644/f556cad3-a28f-4532-a4e6-1cb43de0e868)



## 运行日志(running log)
运行日志会写入running.log(log will be written into the file 'running.log') 

