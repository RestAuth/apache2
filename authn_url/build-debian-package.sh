#!/bin/sh

if [ ! -d debian ]; then
    echo "Please execute this script in the authn_url directory"
    echo "Missing directory debian/"

    exit 1
fi

if [ -z "$1" ]; then
    REVISION=0.0.1+$(svn info|grep Revision:|cut -d' ' -f 2)
else
    REVISION=$1
fi

DIRNAME=libapache2-mod-authn-url-$REVISION

echo "Creating package: $DIRNAME"

rm -rf debian-build

echo "ChangeLog message (leave empty if no message):"
read MSG

if [ ! -z "$MSG" ]; then
    read -p"Urgency (low, medium, high, emergency, or critical)? " URGENCY
    RN=$(grep ^$USER: /etc/passwd|cut -d':' -f 5|cut -d',' -f 1)
    read -p"Your name ($RN)?" RN2
    read -p"Your e-mail?" MAIL
    
    if [ -z "$URGENCY" ]; then
	URGENCY=low
    fi
    
    if [ ! -z "$RN2" ]; then
	RN=$RN2
    fi

    mv debian/changelog debian/changelog.bak

    DATE=$(date '+%a, %d %b %Y %H:%M:%S %z')

    cat <<EOF - debian/changelog.bak > debian/changelog
libapache2-mod-authn-url ($REVISION) unstable; urgency=$URGENCY

  * $MSG

 -- $RN <$MAIL>  $DATE

EOF
    
fi

# create directory
mkdir -p debian-build/$DIRNAME

# copy module stuff in it
cp -rp *.c README debian-build/$DIRNAME/

# and debian/
cp -rp debian/ debian-build/$DIRNAME/

# create svn changelog
svn log > debian-build/$DIRNAME/ChangeLog

# execute builder
cd debian-build/$DIRNAME/
dpkg-buildpackage