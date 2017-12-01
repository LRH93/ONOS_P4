echo "java has been installed"
export JAVA_HOME=/root/java/jdk1.8.0_121
export JRE_HOME=/root/java/jdk1.8.0_121/jre
export CLASSPATH=.:$CLASSPATH:$JAVA_HOME/lib:$JRE_HOME/lib
export PATH=$PATH:$JAVA_HOME/bin:$JRE_HOME/bin
echo "karaf has been installed"
export KARAF_ROOT=/root/ONOS1.6.0/Applications/karaf/apache-karaf-3.0.8/
export PATH=$KARAF_ROOT/bin:$PATH
echo "maven has been installed"
export M2_HOME=/root/ONOS1.6.0/Applications/maven/apache-maven-3.3.9/
export PATH=$PATH:$M2_HOME/bin
echo "onos has been installed"

#两个重要的目录路径
export ONOS_ROOT=/root/ONOS1.6.0/onos-1.6.0/
export onos_p4_dev_ROOT=/root/onos-p4-dev

source $ONOS_ROOT/tools/dev/bash_profile
source $onos_p4_dev_ROOT/tools/bash_profile

export PATH=/opt/idea/idea-IC-171.4424.56/bin:$PATH
export ONOS_APPS=drivers,openflow,proxyarp,mobility

