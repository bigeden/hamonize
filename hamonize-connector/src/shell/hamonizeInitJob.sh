#!/bin/bash  

sleep 10

DATETIME=$(date +'%Y-%m-%d %H:%M:%S')
LOGFILE="/var/log/hamonize/propertiesJob/hamonizeReboot.log"
FILEPATH="/etc/hamonize/propertiesJob/propertiesInfo.hm"
FILEPATH_TMP="/etc/hamonize/propertiesJob/chkpropertiesInfo.hm"

if [ ! -d $LOGFILE ]; then
        touch $LOGFILE
fi


cat /dev/null >$LOGFILE

echo "$DATETIME] resboot==========START" >>$LOGFILE


UUID=$(cat /etc/hamonize/uuid)

# 초기 필수 정보......
CENTERURL="CHANGE_CENTERURL/hmsvc/commInfoData"
# CENTERURL="$1/hmsvc/commInfoData"

DATA_JSON="{\
        \"events\" : [ {\
        \"uuid\": \"$UUID\"\
        } ]\
}"

sleep 3
echo "set pc info url===$CENTERURL" >>$LOGFILE
echo "set pc info data $DATA_JSON" >>$LOGFILE

RETDATA=$(curl -X GET -H 'User-Agent: HamoniKR OS' -H 'Content-Type: application/json' -f -s -d "$DATA_JSON" $CENTERURL)

echo "$DATETIME ]--------> get data ::: " >>$LOGFILE
echo "$RETDATA" >>$LOGFILE

WRITE_DATA=""
FILEPATH_DATA=$(cat ${FILEPATH})
FILEPATH_BOOL=false
if [ -z "$FILEPATH_DATA" ]; then
        FILEPATH_BOOL=true
fi


JQINS=$(echo ${RETDATA} | jq '.pcdata')
JQCNT=$(echo ${RETDATA} | jq '.pcdata' | jq length)

echo "$DATETIME ]-------->center return val is :: " $JQCNT >>$LOGFILE

SET=$(seq 0 $(expr $JQCNT - 1))

for i in $SET; do

        TMP_ORGNM=$(echo ${RETDATA} | jq '.pcdata | .['$i'].svrname' | sed -e "s/\"//g")
        TMP_PCIP=$(echo ${RETDATA} | jq '.pcdata | .['$i'].pcip' | sed -e "s/\"//g")

        WRITE_DATA="$TMP_ORGNM=$TMP_PCIP"

        if [ $FILEPATH_BOOL = "true" ]; then
                echo $WRITE_DATA >>$FILEPATH
        else
                echo $WRITE_DATA >>$FILEPATH_TMP
        fi

done

if [ $FILEPATH_BOOL = "false" ]; then
        DIFF_VAL=$(diff -q $FILEPATH $FILEPATH_TMP)

        if [ -z "$DIFF_VAL" ]; then
                rm -fr $FILEPATH_TMP
        else
                rm -fr $FILEPATH
                mv $FILEPATH_TMP $FILEPATH
        fi
fi

echo "$DATETIME ]-------->agent에서 사용하는 rest 서버 정보 저장 [END] " >>$LOGFILE
#=== agent & pcmngr upgradle ====
sudo apt-get update > /dev/null 2>&1
 


CHK_AGNET_INSTALLED=`dpkg-query -W | grep hamonize-agent | wc -l`
echo "agent install checked is =="$CHK_AGNET_INSTALLED >> $LOGFILE
if [ $CHK_AGNET_INSTALLED = 0  ]; then
        sudo apt-get install hamonize-agent -y >> $LOGFILE
fi

CHK_AGENT=`apt list --upgradable 2>/dev/null | grep hamonize-agent | wc -l`
echo "agent upgrade able is =="$CHK_AGENT >> $LOGFILE
if [ $CHK_AGENT -gt 0  ]; then
        sudo apt-get --only-upgrade install hamonize-agent -y >/dev/null 2>&1
fi


CHK_PCMNGR_INSTALLED=`dpkg-query -W | grep hamonize-process-mngr | wc -l`
echo "pcmngr install checked is =="$CHK_PCMNGR_INSTALLED >> $LOGFILE
if [ $CHK_PCMNGR_INSTALLED = 0  ]; then
        sudo apt-get install hamonize-process-mngr -y >> $LOGFILE
fi

CHK_PCMNGR=`apt list --upgradable 2>/dev/null | grep hamonize-process-mngr | wc -l`
echo "pcmngr upgrade able is =="$CHK_PCMNGR >> $LOGFILE
if [ $CHK_PCMNGR -gt 0  ]; then
        sudo apt-get --only-upgrade install hamonize-process-mngr -y > /dev/null 2>&1
fi


CHK_ADMIN_INSTALLED=`dpkg-query -W | grep hamonize-user | wc -l`
echo "hamonize-user install checked is =="$CHK_ADMIN_INSTALLED >> $LOGFILE
if [ $CHK_ADMIN_INSTALLED = 0  ]; then
        sudo apt-get install hamonize-user -y >> $LOGFILE
fi

CHK_ADMIN=`apt list --upgradable 2>/dev/null | grep hamonize-user | wc -l`
echo "hamonize-user upgrade able is =="$CHK_ADMIN >> $LOGFILE
if [ $CHK_ADMIN -gt 0  ]; then
        sudo apt-get --only-upgrade install hamonize-user -y> /dev/null 2>&1
fi

echo "$DATETIME] resboot==========END" >>$LOGFILE

echo "$DATETIME] hamonize-user 필수 포트 allow 11100==========END" >>$LOGFILE
sudo ufw allow 11100 >>$LOGFILE