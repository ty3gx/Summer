sudo apt-get remove python-nids
wget https://jon.oberheide.org/files/pynids-0.6.1.tar.gz --no-check-certificate
tar -zxvf pynids-0.6.1.tar.gz
sudo apt-get install libpcap-dev pkg-config python-dev libgtk2.0-dev libnet1-dev libnids1.21 libnids-dev
sudo ldconfig
cd pynids-0.6.1/
python setup.py build
sudo python setup.py install
