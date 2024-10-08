# Q-PoPS
Q-PoPS QoS-Aware Power-Optimized Path Selection for Data Center Networks: This project represents the work in our paper submitted to Electronics-MDPI Jurnal "QoS-Aware Power-Optimized Path Selection for Data Center Networks (Q-PoPS)",  DOI: [10.3390/electronics13152976](https://doi.org/10.3390/electronics13152976), Authors: Mohammed Nsaif, Gergely Kovásznai, Ali Malik and Ruairí de Fréin.

### In this project, we provide:

- Part of the code of the paper: Midrange-Case

### Dependencies

#### OS: Ubuntu 20.04.x

>  If you are using Windows or other OS, you can install Ubuntu 20.04 as a Virtual Machine (VM) using Virtual Box. You can download the ISO installer from this [link:](https://www.ubuntu.com/download/desktop)

####  POX controller

> We use [POX](https://github.com/noxrepo/pox) to deploy our management and monitoring SDN application. POX can work in any OS Environment that supports Python 2 or 3. You can install pox as follows:
```
git clone http://github.com/noxrepo/pox
```

#### Mininet

> To simulate an SDN network, we use the popular framework [Mininet](http://mininet.org/). Mininet currently only works in Linux. In our project, we run mininet in an Ubuntu 20.04.2 LTS VM. To get mininet, you can simply download a compressed Mininet VM from [Mininet downloadpage](https://github.com/mininet/mininet/wiki/Mininet-VM-Images) or install it through apt: 
```
sudo apt update 
sudo apt install mininet
```
> or install natively from source:
```
git clone git://github.com/mininet/mininet
cd mininet
git tag  # list available versions
git checkout -b cs244-spring-2012-final  # or whatever version you wish to install
util/install.sh -a
```

#### Openvswitch Installation: 
A collection of guides detailing how to install Open vSwitch in a variety of different environments and using different configurations can find [here](https://docs.openvswitch.org/en/latest/intro/install/). However, for Ubuntu as follows:

```
sudo apt-get install openvswitch-switch
```

#### Distributed Internet Traffic Generator
> D-ITG is a platform capable of producing traffic at the packet level accurately replicating appropriate stochastic processes for both IDT (Inter Departure Time) and PS (Packet Size) random variables (exponential, uniform, Cauchy, normal, Pareto, ...).
D-ITG supports both IPv4 and IPv6 traffic generation and it is capable of generating traffic at network, transport, and application layer.
Install and usage guidelines, you can be found [here](https://traffic.comics.unina.it/software/ITG/)

> Quique installation as follows:

```
sudo apt-get install D-ITG
```


### SDN Applications Usage

In this project, we created two POX applications, and the source codes are stored in the  [Q-PoPS](https://github.com/nsaif86/Q_PoPS.git). The first component, DCN9, is responsible for consolidating the flows in the one-link as much as possible. The second is the Monitoring Model. The method is clearly described in our paper.



To run the applications, copy the two Python programs into the pox.ext.optimization.PQ.startup folder of the pox directory and open two terminal windows, execute the following command:

In the first terminal
```
sudo ./pox.py   optimization.PQ.startup

```
In the second terminal
```
sudo python3  fat_tree.py
```
See this [video](https://encyclopedia.pub/video/video_detail/1334), which includes a practical example of running the code at the end.

Please, if you find the code useful, cite our work.

to cite :

@article{nsaif2024qos,
  title={QoS-Aware Power-Optimized Path Selection for Data Center Networks (Q-PoPS)},
  author={Nsaif, Mohammed and Kov{\'a}sznai, Gergely and Malik, Ali and de Fr{\'e}in, Ruair{\'\i}},
  journal={Electronics},
  volume={13},
  number={15},
  pages={2976},
  year={2024},
  publisher={Multidisciplinary Digital Publishing Institute}
}

