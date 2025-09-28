#/bin/sh
# A SIMPLE INSTALLER AND SETUP SCRIPT FOR SPLUNK.
# TESTED ON DEVUAN LINUX
# AUTHOR: John Rogers
# DATE:   Sep 28, 2025


installPath="/opt/"

cd $installPath

splunkUserName="splunk"


# Check if the user exists
if id "$splunkUserName" >/dev/null 2>&1; then
    echo "User \"$splunkUserName\" already exists."
else
    # Create the user
    useradd -d $installPath --system "$splunkUserName"
    if [ $? -eq 0 ]; then
        echo "User $splunkUserName has been created successfully."
    else
        echo "Failed to create user $splunkUserName."
    fi
fi

sleep 0.5

splunkPackageName="splunk-package.tgz"
splunkDownloadLink="https://download.splunk.com/products/splunk/releases/10.0.0/linux/splunk-10.0.0-e8eb0c4654f8-linux-amd64.tgz"

if [ -f "$splunkPackageName" ]; then
    echo "File \"$splunkPackageName\" already downloaded."
else
    echo "Downloading Splunk..."
    wget -O $splunkPackageName $splunkDownloadLink || { echo "Failed to download Splunk. Check the link!"; exit; }
    echo "    Done"
fi

sleep 0.5

if [ -d "./splunk" ]; then
    echo "Splunk is already installed! Delete $installPath/splunk directory and retry."
    exit
else
    echo "Unpacking $splunkPackageName to $installPath"
    tar -xzf ./$splunkPackageName
fi
echo "    Done"

sleep 0.5

echo "Changing ownership of $installPath/splunk to $splunkUserName"
chown -R $splunkUserName:$splunkUserName $installPath/splunk
echo "    Done"

sleep 0.5

echo "Will start Splunk for the first time. You have to accept the EULA!"
sleep 4
#./splunk/bin/splunk start --accept-license --answer-yes --no-prompt
./splunk/bin/splunk start

sleep 0.5

echo "Installing init script"
./splunk/bin/splunk enable boot-start -user $splunkUserName
echo "    Done"

sleep 0.5

echo "Creating wrapper script /bin/splunk"
printf "#!/bin/sh\n\nsu -c \"$installPath/splunk/bin/splunk $1\" $splunkUserName" > /bin/splunk
chown root /bin/splunk
chmod 700 /bin/splunk
echo "    Done. You can now access Splunk with the command \"splunk start\""
printf "\nComplete!\n\n"
