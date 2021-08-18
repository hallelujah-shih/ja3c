# ja3c
```
XDP采集tls hello，并在用户空间计算ja3 client的hash值

测试代码
```

## 简单使用
```
go build
cd bpf && make

// attach
./ja3c -c cfg.json attach

// detach
./ja3c -c cfg.json detach
```
