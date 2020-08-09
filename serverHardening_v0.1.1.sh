#!/bin/bash
INIT=$(date +%s)
echo "##### Iniciando ejecucion - $(date)#####"
echo # Validar asignacion correcta de GID y UID."
UIDMIN=$(cat /etc/login.defs | grep UID_MIN | sed 's/\s\+/,/g' | cut -d "," -f 2)
GIDMIN=$(cat /etc/login.defs | grep GID_MIN | sed 's/\s\+/,/g' | cut -d "," -f 2)
UIDMIN=${UIDMIN%$'\n'*}
GIDMIN=${GIDMIN%$'\n'*}
#VAR=$(echo $UIDMIN | tr -d '\r')
#IFS='\r'; read -a arr1 <<< $UIDMIN
UIDINT=$((UIDMIN))
if [ $UIDINT -ge 1000 ]; then
    echo "# El valor para UID_MIN es: $UIDINT - es correcto."
else
    echo "# El valor para UID_MIN es: $UIDINT - es incorrecto - se va a modificar para usar: 1000"
    sed -i 's/^UID_MIN.*/UID_MIN                 1000/g' /etc/login.defs
    sed -i 's/^UID_MAX.*/UID_MAX                 60000/g' /etc/login.defs
fi
#IFS='\r'; read -ra arr2 <<< $GIDMIN
GIDINT=$((GIDMIN))
if [ $GIDINT -ge 1000 ]; then
    echo "# El valor para GID_MIN es: $GIDINT - es correcto."
else
    echo "# El valor para GID_MIN es: $GIDINT - es incorrecto."
    sed -i 's/^GID_MIN.*/GID_MIN                 1000/g' /etc/login.defs
    sed -i 's/^GID_MAX.*/GID_MAX                 60000/g' /etc/login.defs
fi
echo "# Finalizada la validacion del UID_MIN y GID_MIN."
echo "# Insertar la variable USEPASSWDQC en el archivo /etc/sysconfig/authconfig" 
sudo sed -i 's/USEPASSWDQC=no/USEPASSWDQC=yes/g' /etc/sysconfig/authconfig
echo "# Validando el cambio"
cat /etc/sysconfig/authconfig | grep USEPASSWDQC
echo "# Configuracion para las contrasenias de los usuarios."
echo "# Asignar el maximo de caducidad de contrasenia a 30 dias."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t30/g' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/g' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t10/g' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t10/g' /etc/login.defs
echo "# Agregando configuracion para bloquear al usuario 30 minutos por intentos de login fallidos (6)."
sed -i '5iauth        required       pam_faillock.so preauth silent audit deny=6 unlock_time=1800' /etc/pam.d/system-auth
sed -i '8iauth        [default=die]  pam_faillock.so authfail audit deny=6 unlock_time=1800' /etc/pam.d/system-auth 
echo "# Insertar la variable TMOUT para terminar la sesion del usuario despues de 15 min de inactividad."
VTMOUT=$(cat /etc/profile | grep TMOUT)
if [ -z "$VTMOUT" ]; then
    sed -i '10G' /etc/
    sed -i '11iTMOUT=900' /etc/profile
else 
    sed -i 's/^TMOUT.*/TMOUT=900/g' /etc/profile
fi
echo "# Validando el cambio."
cat /etc/profile | grep TMOUT
echo "# Insertar la variable para que las cuentas inactivas despues de 90 dias se inhabiliten."
sudo sed -i 's/INACTIVE=-1/INACTIVE=90/g' /etc/default/useradd
echo "# Validando el cambio."
cat /etc/default/useradd | grep INACTIVE
echo "# Buscando archivos con SUID."
for file in `find / -perm /4000`
do
	echo "# Archivo SUID encontrado: $file - removiendo bit SUID."
	chmod u-s $file 
done
echo "# Buscando archivos con SGID."
for file1 in `find / -perm /2000`
do 
	echo "# Archivo SGID encontrado: $file1 - removiendo bit SGID."
	chmod g-s $file1
	echo "# Removido del archivo."
done
echo "# Validar que los permisos del directorio /home son 755."
HOMEPERM=$(stat -c '%a' /home)
if [ "$HOMEPERM" != "755" ]; then
	echo "# Los permisos son incorrectos, realizando el cambio."
	chmod 755 /home
else 
	echo "# Los permisos son correctos: $HOMEPERM"
fi
echo "# Validar que el dueño del archivo /etc/passwd es root."
OWNER=$(stat -c '%U' /etc/passwd)
if [ "$OWNER" != "root" ]; then
	echo "El usuario del archivo es incorrecto, realizando el cambio."
	chown root:root /etc/passwd
else
       echo "# El usuario del archivo es correcto."	
fi
echo "# Asegurarse que todos los archivos del sistema pertenecen a un grupo y tienen duenio."
for file2 in `find / -nogroup -nouser`
do 
	echo "# Archivo sin duenio encontrado: $file2"
done
echo "# Los archivo en el directorio /etc/rc* y /etc/init.d deben tener permisos 754 o menores y ser propiedad de root."
DIR="/etc/init.d/*;/etc/rc*/"
IFS=';' read -ra ADIRS <<< "$DIR"
for dir in "${ADIRS[@]}"
do 	
	for filename in `find $dir -print`
	do
		FPERM=$(stat -c '%a' "$filename")
		FPERM=$((FPERM))
		FUSER=$(stat -c '%U' "$filename")
		if [ -L "$filename" ]; then
		    :
		else
       		if [ $FPERM -le 754 ]; then 
		    #echo "# El archivo tiene los permisos correctos: $FPERM ."
		    :
		    else 
		        echo "# El archivo: $filename tiene permisos incorrectos: $FPERM - cambiando por 754."
			    chmod 754 "$filename"
	        fi
		fi
		if [ "$FUSER" == "root" ]; then
			#echo "# Archivo: $filename con propietario correcto: $FUSER"			
			:
		else 
		    echo "# Archivo: $filename con propietario incorrecto: $USER - asignando a root."
			chown root:root "$filename"
		fi		
	done
done
echo "# Revisar que los archivos no tienen mayores permisos que los del usuario."
DIR="/etc/*;/bin/*;/usr/*;/sbin/*"
IFS=';' read -ra DIRS <<< "$DIR"
for DIRP in "${DIRS[@]}"
do 
	for filename in `find $DIRP`
	do 
		OWNER=$(stat -c '%a' "$filename" | cut -c 1)
		GROUP=$(stat -c '%a' "$filename" | cut -c 2)
		OTHER=$(stat -c '%a' "$filename" | cut -c 3)
		OWNER=$(($OWNER))
		GROUP=$(($GROUP))
		OTHER=$(($OTHER))
		if [ $OWNER -lt $GROUP ] || [ $OWNER -lt $OTHER ]; then
			echo "# Los permisos del propietario son incorrectos: P-$OWNER::G-$GROUP::O-$OTHER" 
			chmod u+rwx "$filename"
		else 
			#echo "# Los permisos del archivo $filename son correctos."
			:
		fi	
	done
done
echo "# Validar que los permisos en los directorios /etc;/bin;/usr;/sbin sean 755 o mas restrictivos."
DIRS="/etc/*;/bin/*;/usr/*;/sbin/*;"
IFS=';' read -ra ADIRS <<< "$DIRS"
for dir in "${ADIRS[@]}"
do
       for file in `find $dir`
       do 
	       if [ -d "$file" ]; then
		       #echo "# Procesando los archivos en el directorio: $file"
			   :
	       fi
	       PERM=$(stat -c '%a' $file)
	       PERM=$((PERM))
	       if [ $PERM -le 755 ]; then
		       #echo "# Permisos correctos para el archivo: $file"
		       :
	       else 
		       echo "# Permisos incorrectos para el archivo: $file, aplicando permisos 755"
		       chmod 755 "$file"
	       fi
       done	       
done
echo "# Validar que el archivo /etc/shadow tiene permisos 400 y el propietario es root."
PERM=$(stat -c '%a' /etc/shadow)
PERM=$((PERM))
USER=$(stat -c '%U' /etc/shadow)
if [ $PERM -le 400 ]; then
    echo "# El archivo /etc/shadow tiene los permisos correctos."
else 
    echo "# El archivo /etc/shadow tiene los permisos: $PERM incorrectos - cambiando permisos a 400."
	chmod 400 /etc/shadow
fi
if [ $USER == "root" ]; then
   echo "# El archivo /etc/shadow pertenece a $USER "
else
   echo "# El archivo /etc/shadow no pertenece a root: $USER - reasignando propietario."
   chown root:root /etc/shadow
fi
echo "# Validar que el archivo /etc/passwd tiene permisos 644 y el propietario es root."
PERM=$(stat -c '%a' /etc/passwd)
PERM=$((PERM))
USER=$(stat -c '%U' /etc/passwd)
if [ $PERM -le 644 ]; then
    echo "# El archivo /etc/passwd tiene los permisos correctos: $PERM "
else 
    echo "# El archivo /etc/passwd tiene los permisos incorrectos: $PERM - asignando permisos 644."
	chmod 644 /etc/passwd
fi
if [ "$USER" == "root" ]; then
   echo "# El archivo /etc/passwd pertenece a $USER" 
else 
    echo "# El archivo /etc/passwd pertenece a $USER - reasignando propietario a root." 
	chown root:root /etc/passwd
fi
echo "# Verificar que los permisos en los archivos de bitacora del sistema /var/log* sean 640."
for file in `find /var/log*/`
do 
   PERM=$(stat -c '%a' $file)
   PERM=$((PERM))
   if [ $PERM -le 640 ]; then
      #echo "# Los permisos para el archivo: $file son correctos: $PERM"
      :
   else 
      echo "# Los permisos para el archivo: $file son incorrectos: $PERM"
      chmod 640 "$file"
   fi	  
done 
echo "# Establecer los permisos 400 en los archivos de tareas programadas /etc/crontab*."
for file in `find /etc/cron*/`
do 
   PERM=$(stat -c '%a' $file)
   PERM=$((PERM))
   if [ $PERM -le 400 ]; then
      #echo "# El archivo $file tiene los permisos correctos: $PERM"
      :
   else 
      echo "# El archivo $file tiene los permisos incorrectos: $PERM"
	  chmod 400 "$file"
   fi
done
echo "# Validar que los permisos de los arhcivos inetd.conf, hosts.lpd, inittab, cronlog.conf tienen permisos 600 y los archivos at.allow, at.deny con permisos 400"
FILES600="inetd.conf;hosts.lpd;inittab;cronlog.conf"
FILES400="at.allow;at.deny"
IFS=';' read -ra AFILES <<< "$FILES600"
for file in "${AFILES[@]}"
do 
   sfile=`find / -name "$file"`
   if [ -f "$sfile" ]; then
      PERM=$(stat -c '%a' "$sfile")
	  PERM=$((PERM))
	  if [ $PERM -ne 600 ]; then
	     echo "# El archivo: $file tiene permisos incorrectos: $PERM - se van a cambiar por 600."
		 chmod 600 "$sfile"
	  else 
	     #echo "# El archivo $file tiene los permisos correctos: $PERM ."
	     :
	  fi
	else 
	   echo "# El archivo $file no existe."
   fi
done
IFS=';' read -ra AFILES1 <<< "$FILES400"
for file in "${AFILES1[@]}"
do
    sfile=`find / -name "$file"`
   if [ -f "$sfile" ]; then
      PERM=$(stat -c '%a' "$sfile")
	  PERM=$((PERM))
	  if [ $PERM -ne 400 ]; then
	     echo "# El archivo: $file tiene permisos incorrectos: $PERM - se van a cambiar por 400."
		 chmod 400 "$sfile"
	  else 
	     #echo "# El archivo: $file tiene permisos correctos: $PERM ."
	     :
	  fi
   else 
      echo "# El archivo $file no existe."
   fi
done
echo "# Asignar permisos  077 a root y 027 a usuarios en el archivo /etc/profile"
sed -i 's/umask 002/umask 027/g' /etc/profile
sed -i 's/umask 022/umask 077/g' /etc/profile
echo "# Buscar los archivos y directorios con sticky bit y removerlo."
for file in `find / -type d -perm /2`
do 
   echo "# Encontrado archivo: $file removiendo sticky bit."
   chmod -t "$file"
done
echo "# Los archivos services, utmp, motd, wtmp, mtab, syslog.pid, group, /usr/share/man, /usr/share/info, /usr/share/infopage deben tener permisos 644."
FILES="services;utmp;motd;wtmp;mtab;syslog.pid;group"
DIRS="/usr/share/man;/usr/share/info;/usr/share/infopage"

IFS=';' read -ra AFILES <<< "$FILES"
for file in "${AFILES[@]}"
do 
    sfile=`find / -name "$file"`
	if [ -f "$sfile" ]; then
	    PERM=$(stat -c '%a' "$sfile")
		PERM=$((PERM))
		USER=$(stat -c '%U' "$sfile")
		if [ "$USER" == "root" ]; then 
            #echo "# El archivo: $sfile pertenece a $USER "
	    :
	    else 
		    echo "# El archivo: $sfile pertenece a $USER - reasignando propietario a root."
			chown root:root "$sfile"
		fi 
		if [ $PERM -eq 644 ]; then
		    #echo "# El archivo: $sfile tiene los permisos correctos $PERM ." 
		    :
		else 
		    echo "# El archivo: $sfile tiene los permisos incorrectos: $PERM - cambiando permisos a 644." 
			chmod 644 "$sfile"
		fi	    
	else 
	    echo "# El archivo $file no existe."
    fi
done
IFS=';' read -ra ADIRS <<< "$DIRS" 
for dir in "${ADIRS[@]}"
do 
    if [ -d "$dir" ]; then
	    PERM=$(stat -c '%a' "$dir")
		PERM=$((PERM))
		USER=$(stat -c '%U' "$dir")
		if [ "$USER" == "root" ]; then
		    #echo "# El directorio $dir pertenece a $USER ."
		    :
		else 
		    echo "# El directorio $dir pertenece a $USER - cambiando propietario a root."
			chown root:root "$dir"
		fi
		if [ $PERM -eq 644 ]; then 
		   #echo "# El directorio: $dir tiene los permisos correctos $PERM ."
		   :
		else 
		    echo "# El directorio: $dir tiene los permisos incorrectos $PERM - cambiando a 644." 
			chmod 644 "$dir"
		fi		
    else 
        echo "# El directorio: $dir no existe."	
    fi
done
echo "# El archivo de sistema /etc/fstab debe tener permisos 664 y debe ser propiedad de root."
PERM=$(stat -c '%a' /etc/fstab)
PERM=$((PERM))
USER=$(stat -c '%U' /etc/fstab)
if [ $PERM == 664 ]; then
   echo "# Los permisos para el archivo /etc/fstab son correctos."
else
   echo "# Los permisos para el archivo /etc/fstab son incorrectos, aplicando permisos 664."
   chmod 664 /etc/fstab
fi
if [ "$USER" == "root" ]; then
   echo "# El usuario del archivo /etc/fstab es correcto."  
else
   echo "# El usuario del archivo /etc/fstab es incorrecto $USER, cambiando a root."
   chown root:root /etc/fstab
fi
echo "# Limitar y justificar los permisos del directorio /var/crash, debe ser de root y solo dar permisos completos a root:root."
PERM=$(stat -c '%a' /var/crash)
PERM=$((PERM))
USER=$(stat -c '%U' /var/crash)
GROUP=$(stat -c '%G' /var/crash)
if [ "$USER" == "root" ]; then
    echo "# El usuario es correcto: $USER ."
else 
    echo "# El usuario es incorrecto: $USER - cambiando propietario a root."
	chown root:root /var/crash
fi
if [ "$PERM" -gt 711 ]; then
    echo "# Los permisos del archivo son incorrectos: $PERM - cambiando permisos por 711."
	chmod 711 /var/crash
else 
    echo "# Los permisos para el archivo son correctos."
fi
echo "# Asegurarse de que el archivo /etc/shadow solo es accesible por root y que utiliza un algoritmo robusto de hashing."   
PERMS=$(stat -c '%a' /etc/shadow)
PERMS=$((PERMS))
USER=$(stat -c '%U' /etc/shadow)
if [ "$USER" != "root" ]; then
    echo "# El usuario no es root: $USER ."
	chown root:root /etc/shadow
elif [  $PERM -gt 400 ]; then
    echo "# Los permisos del archivo son muy altos: $PERM ."
	chmod 400 /etc/shadow
else 
    echo "# El usuario y los permisos son correctos."
fi
echo "# Validando el algoritmo de hashing para las contrasenias."
str=" password hashing algorithm is "
strCmd=`authconfig --test | grep hashing`
lenStr=${#str}
lenStrCmd=${#strCmd}
algLen=$(($lenStrCmd - $lenStr))
hash=${strCmd:lenStr:algLen}
if [ "$hash" != "sha512" ]; then
    echo "# El algoritmo de hash no es mas robusto: $hash - cambiando por el mas robusto (sha512)."
	authconfig --passalgo=sha512 --update
else 
    echo "# El algoritmo de hash: $hash es robusto."
fi
echo "# Instalar el software necesario para habilitar autenticación MFA."
echo "# Instalando paquetes EPEL." 
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
echo "# Instalando modulos PAM de Google Authenticator." 
yum install -y google-authenticator
#sed -i -e '$aauth       required      pam_google_authenticator.so nullok' /etc/pam.d/sshd
#sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication   yes/g' /etc/ssh/sshd_config
#sed -i -e '$aAuthenticationMethods publickey,password publickey,keyboard-interactive' /etc/ssh/sshd_config
#systemctl restart sshd.service
echo "# Actualizando las aplicaciones."
yum -y apt-get update
echo "# El servidor debe mostrar un mensaje al inicio de cualquier sesión en el que se indique la sensibilidad de los datos."
cp /etc/motd /tmp/motd.bak
cp /dev/null /etc/motd
echo "" >> /etc/motd
echo "La información contenida en este equipo es propiedad de Grupo Sanborns," >> /etc/motd
echo "si inicia sesión de forma no autorizada se hará acreedor a las sanciones" >> /etc/motd
echo "que dicte la legislación correspondiente aplicable al contenido y lugar" >> /etc/motd
echo "donde reside el servidor" >> /etc/motd
echo "# Validar si la variable de ambiente PATH tiene caracteres en blanco."
echo "" >> /etc/motd
PATHVAL="$PATH"
if [[ $PATHVAL =~ [' '] ]]; then
    echo "# La variable de ambiente PATH contiene caracteres en blanco."
else 
    echo "# La variable de abmiente PATH no contiene caracteres en blanco."
fi
echo "# Validando la configuracion de la red."
SYNCOOKIE=`sysctl -n net.ipv4.tcp_syncookies`
IPFORWARD=`sysctl -n net.ipv4.ip_forward`
if [ $SYNCOOKIE -ne 1 ]; then 
    echo "# syncookies inactivo, activando."
	$VARSYNCOOKIE=`cat /etc/sysctl.conf | grep net.ipv4.ip_forward`
	if [ -z "$VARSYNCOOKIE" ]; then  
	    echo "# El archivo de configuracion /etc/sysctl.conf no contiene la entrada, agregandola."
		echo "net.ipv4.tcp_syncookies 1" >> /etc/sysctl.conf
	    sysctl -p
	else 
	    echo "# Activando syncookies." 
	    sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies 1/g' /etc/sysctl.conf
		sysctl -p
	fi
else 
    echo "# syncookies activo."
fi
if [ $IPFORWARD -ne 0 ]; then
    echo "# ip forward activo, desactivando."
	$VARIPFORWARD=`cat /etc/sysctl.conf | grep net.ipv4.ip_forward`
	if [ -z "$VARIPFORWARD" ]; then 
	    echo "# El archivo /etc/sysctl.conf no contiene la configuracion, agregandola."
		echo "net.ipv4.ip_forward 0" >> /etc/sysctl.conf
		sysctl -p
	else 
	    echo "# Desactivando ip forward."
		sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward 0/g' /etc/sysctl.conf
		sysctl -p
	fi
else 
    echo "# ip forward inactivo."
fi
echo "# Validando version de SSH para el sistema."
SSHVER=$(ssh -V 2>&1)
if [[ $SSHVER == *'OpenSSH_7.4'* ]]; then
    echo "La version SSH es la mas reciente para el sistema."
else 
    echo "Actualizando la version de SSH." 
	yum update openssh-server
fi
echo "# Revisar los permisos del siguiente archivo: /var/log/audit/audit.log debe tener permisos 640."
USER=$(stat -c '%U' /var/log/audit/audit.log)
PERM=$(stat -c '%a' /var/log/audit/audit.log)
PERM=$((PERM))
if [ $PERM -le 640 ]; then
    echo "# Los permisos del archivo son correctos: $PERM"
else
    echo "# Los permisos del archivo son incorrectos: $PERM - asignando permisos 640."
	chmod 640 /var/log/audit/audit.log
fi
if [ "$USER" != "root" ]; then
    echo "# El usuario propietario del archivo no es root: $USER - cambiando el propietario a root"
	chown root:root /var/log/audit/audit.log
else 
    echo "# El usuario propietario del archivo es: $USER"
fi
echo "# Agregando reglas de auditoria para eventos de seguridad, logon, logoff, ejecucion de su, sudo, useradd, groupadd." 
echo "# logon/logoff exitosos y no exitosos" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/utmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/security/opasswd -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/group -p wa -k auth" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/passwd -p wa -k auth" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/gshadow -p wa -k auth" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/shadow -p wa -k auth" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/security/opasswd -p wa -k auth" >> /etc/audit/rules.d/audit.rules
echo "# Proteccion de las bitacoras." >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/audit/ -k audit-logs" >> /etc/audit/rules.d/audit.rules
echo "# Ejecucion de archivos administrativos" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F exe=/bin/su -F arch=b64 -S execve -k execution_bin_id" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F exe=/bin/sudo -F arch=b64 -S execve -k execution_bin_id" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F exe=/bin/useradd -F arch=b64 -S execve -k execution_bin_id" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F exe=/bin/groupadd -F arch=b64 -S execve -k execution_bin_id" >> /etc/audit/rules.d/audit.rules
echo "# Eventos de configuracion de red."
echo "-a always,exit -F arch=b64 -S socket -F success=1 -k network" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/hostname -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "# Listando los procesos y puertos encendidos."
netstat -tulpn
netstat -tulp
FIN=$(date +%s)
ELAPSED=$((FIN - INIT))
function muestraFecha {
  local T=$1
  local D=$((T/60/60/24))
  local H=$((T/60/60%24))
  local M=$((T/60%60))
  local S=$((T%60))
  (( $D > 0 )) && printf '%d dias ' $D
  (( $H > 0 )) && printf '%d horas ' $H
  (( $M > 0 )) && printf '%d minutos ' $M
  (( $D > 0 || $H > 0 || $M > 0 )) && printf 'and '
  printf '%d ses\n' $S
}
ELAPSED=`muestraFecha $ELAPSED`
echo "##### Transcurrido: $ELAPSED #####"
echo "##### Fin - $(date) #####"
