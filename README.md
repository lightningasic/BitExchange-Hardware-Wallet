## 本项目基于:
https://github.com/trezor/trezor-mcu/

## 构建说明: 

### 使用BitExchange提供的docker镜像直接编译（推荐）
1、下载BitExchange firmware 编译环境镜像

```sh
docker pull tolak/bitexchange-firmware-buildenv
```

下载后运行容器

### 自己搭建编译环境
系统环境：ubuntu:14.04 32bit

1、构建BitExchange 编译环境

```sh
$apt-get update
$sudo apt-get install -y build-essential  git  python python-pip libssl-dev
$pip install ecdsa
$wget wget https://launchpadlibrarian.net/186124160/gcc-arm-none-eabi-4_8-2014q3-20140805-linux.tar.bz2 
$tar vxf gcc-arm-none-eabi-4_8-2014q3-20140805-linux.tar.bz2
$export PATH=$PATH:$(HOME)/gcc-arm-none-eabi-4_8-2014q3/bin
```

终端上能运行arm-none-eabi-gcc 表示编译环境构建完成

2、下载stm32所用的libopencm3到vendor目录

```sh
$git clone https://github.com/libopencm3/libopencm3.git
```

3、编译库

```sh
$cd  libopencm3
$git checkout 7dbb93c78411b37bec64b5ca5be55076b0ab1b15
$make
```


## 编译说明(docker内编译)
1、下载firmware source code

```sh
git clone https://github.com/lightningasic/BitExchange-Hardware-Wallet.git
```

2、拷贝source code到docker容器(如果在主机上编译则不用）

```sh
docker cp BitExchange-Hardware-Wallet <containerID>:/home/root
```

3、进入容器编译firmware(在主机编译步骤一致）

- 编译protobuf文件
```sh
$cd BitExchange-Hardware-Wallet/firmware/protob
$make
```

- 编译firmware
```sh
$cd BitExchange-Hardware-Wallet
$make
$cd BitExchange-Hardware-Wallet/firmware
$make
```

得到bitexchange.bin 二进制文件

4、自已手动发布一个非官方firmware固件,进入firmware目录

```sh
$make release
```

其中fingerprint：xxxxxxx为编译firmware二进制文件的hash值
得到一个bitexchange-x.x.x.bin.hex的十六进制文件，此文件可用后面的刷新固件程序将它烧进BitExchange硬件钱包里面

5、验证firmware程序
- 用bitexchange-tools刷写固件
- 可以在校验固件的步骤，对比编译出来的fingerprint值是否与升级后的一致，也可对比相关值与官方更新所得到的值是否一致。

注意：验证firmware的hash值时，编译的版本一定要与所验证的版本一致。
