/*
  This file is part of xlogin display manager

  Copyright (C) 2021 Enrique Dominguez Pinos

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#include "defconfig.h"
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.44.0"
#endif

#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,8,0)
#define HIDEPID_INVISIBLE "hidepid=invisible"
#else
#define HIDEPID_INVISIBLE "hidepid=2"
#endif

#include <features.h>

#if __GLIBC_PREREQ(2,32)
#define SECURE_FCHMODAT 1
#endif

#ifndef USE_PAM
#include <sys/types.h>
#include <signal.h> //kill,signal,(killpg)
#include <unistd.h> //access,pause,getpass,ttyname,(getsid/getpgid),dup2
#include <stdio.h>
#include <stdlib.h> //clearenv
#include <grp.h> //setgroups,initgroups
#include <shadow.h>//getspnam
#include <string.h>//strcmp,explicit_bzero,strerror,memset
#endif
#include <sys/wait.h> //wait
#include <sys/stat.h> //chmod,stat
#include <sys/vfs.h> //statfs
#include <sys/prctl.h> //prctl
#include <fcntl.h> //open

#include <syslog.h>//syslog

#include <pwd.h>//getpwnam
#include <grp.h>//getgrgid

#include <wordexp.h>

#include <utmp.h>
//#include <utmpx.h>
#ifndef _PATH_UTMP
#include <paths.h>
#endif

#define XSOCKETDIR _PATH_TMP ".X11-unix/"

#include <errno.h>
#include <libgen.h> //dirname(3)

#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h> //misc_conv
#include <time.h> //time
#define CONFIG_PAM "/etc/pam.d/xlogin"
#endif

//#include <stdint.h> //(uintmax_t)
//#include <.h>

//#include "getpass.inc"

#include <stdbool.h>
/*
//typedef int bool;
#define bool int
#define true 1
#define false 0
*/

//#define TESTUNIT true

//globals
#define MCOOKIE_SZ 34 //get value with: echo $(( $(mcookie | wc -m) +1))
#define AUTHFILE_SZ 256
 //BUG: ver limits.h
//username, groupname
#define FIELDSZ 16
//#define PASS_MAX 16
//home,shell paths
#define SPFIELDSZ 50
#define MAX_PATH 256
//#define MAX_LINE 512
#define ERR_MSG 256

//"rwx"'\0'
#define PERMSZ 4
//"u-srwx,g-srwx,o-srwx"'\0' 6*3=18+2=20+1=21
#define CHMODSZ 21
//"rwxrwxrwxrwx"'\0' 4*3=12+1=13 (full perms)
#define FPERMSZ 13

#define DEFAULT_XSERVER "Xorg"
//seconds
#define LOGIN_TIMEOUT 20
#define XSERVER_WAIT_TIMEOUT 10

#define ROOTUSER "root"
//#define AUTHUSER "authuser" //don't do anything as root
//set to -1 to disable check over utmpgroup

#ifndef UTMP_GROUP_NAME
#define UTMP_GROUP_NAME "utmp"
#endif

#define DEFAULT_PATH "/usr/bin:/bin"
//single word and no params
#define DEFAULT_SESSION "openbox"

#define DEV_NULL "/dev/null"

//config files dir
#define XLOGINDIR "/etc/xlogin"

#define PROC_YAMA "/proc/sys/kernel/yama/ptrace_scope"
#define YAMA_PROFILE '3'
//read 'man crypt(3)'
#define CRYPT_ID '6'
#define PROC_MOUNTS "/proc/self/mounts"
//man statfs(2)
#define PROC_SUPER_MAGIC 0x9fa0

#ifndef USE_PAM
#define ENV_FILE "/etc/environment.d/10-gentoo-env.conf"
#endif

//#define strzero(str) explicit_bzero(str,strlen(str))

//store
static struct userdata {
  char name[FIELDSZ];
  char group[FIELDSZ];
  char shell[SPFIELDSZ];
  char home[SPFIELDSZ];
  uid_t uid;
  gid_t gid;
} user;

#ifdef USE_PAM
struct pamdata {
  pam_handle_t* pamh;
  int result;
};
#else
struct pamdata {
  //  int* pamh;
  //int result;
  short result;
};
#endif

//required: newline each line of xloginrc or sessionrc file

//BUG: inicializar todo e intentar poner const a todo lo que es const (lo protege el compilador con algo??)

//Security
// Denegate root login
// MOUNT de PROC con hidepid=2 ??
// groupname==username to login (protect socket)
// home folder must be o-rwx (protect socket)
// Xserver params no user selectable (no listen tcp, no listen local; avoid world access to tcp or abstract socker)
// Xclients no user selectable (avoid xsm because local abstract socket)
// pkill de todos los procesos al cerrar X (que son hijos de xlogin) [mismo process group]

//prototipos
static void trim_spaces(char *const sessionbin, char** outcharptr);
static int splitcount(char arr[], const char delim[]);
static void splitasign(int i, const char delim[], char arr[],/*out*/ char* prog[]);
static bool splitstr(const char delim[], char arr[], char ***ptrprog);
#ifndef USE_SYSLOG
static void tmpsyslog(const char *const msg);
#endif
static void ewritelog(const char *const msg);
static void writelog(const char *const msg);
static bool set_uid_gid(const char *const username, const uid_t, const gid_t gid);
static FILE* nspopen(char *const prog[], const char *const mode);
static int nspclose(FILE* fp);
static bool run_mcookie(char[MCOOKIE_SZ]);
static bool has_shell(void);
static bool setup_xauth(char[AUTHFILE_SZ]);
static void sigIgnore(const int sigNum);
static void sigAbort(const int sigNum);
static pid_t start_xserver(char *const default_vt);
static bool build_and_test_path(const char *const template, const char *const filename, const char permMsg[], const char filetype, const char perm[],
				char filepath[MAX_PATH]);
static bool exists_xloginrc(char xloginrc[MAX_PATH]);
static bool exists_proc(char procdir[MAX_PATH]);
static bool valid_not_commented_or_null_line(const char sessionbin[MAX_PATH]);
static bool valid_yama_line(const char str[MAX_PATH]);
static bool valid_proc_line(const char str[MAX_PATH]);
static bool read_valid_line_from_file(FILE* *const fp_ptr, const char *const filename, bool (*validate)(const char *const), /*out*/ char line[MAX_PATH]);
static bool action_proc_line(bool *const success, const bool hasShell, char line[MAX_PATH]);
static bool action_yama_line(bool *const success, const bool hasShell, char line[MAX_PATH]);
static bool action_first_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]);
static bool validate_fstype(const char *const path, __fsword_t fstype);
static bool is_proc_secure(void);
static void fork_prog_(char *const prog[], pid_t* child_pid);
static void fork_prog(const bool hasShell, char sessionbin[MAX_PATH], pid_t* child_pid);
static bool cmd2buf(const bool eof, char sessionbintmp[MAX_PATH], char sessionbin[MAX_PATH]);
static bool action_login_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]);
static bool action_logout_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]);
static bool got_valid_line(const bool hasShell, const char sessionrc[MAX_PATH], bool (*validate)(const char *const),
			   bool (*action)(bool *const, const bool, char[MAX_PATH]), char sessionbin[MAX_PATH]);
static bool include(const char* *const patterns,const char *const str);
#ifndef USE_PAM
static bool valid_env_line(const char line[MAX_PATH]);
static bool action_env_line(bool *const success, const bool hasShell, char line[MAX_PATH]);
static bool load_env(void);
#else
static bool exists_pamconfig(void);
static bool load_pam_env(const struct pamdata *const pampst);
#endif
static bool waitpid_with_log(const pid_t child_pid);
static bool waitsid_with_log(const pid_t child_sid);
static void start_session(struct pamdata *const pampst);
static void strzero(char *const);
static bool check_parents_(const char *const permMsg, const char *const perm, char *const dir);
static bool check_parents(const char* permMsg, const char* perm, const char *const dir);
static short perm_str_to_octal(const char* perm);
static void perm_octal_to_str(const short octal,char perm[PERMSZ]);
static void perm_octal_to_str_ext(const short octal,char perm[PERMSZ]);
static bool argv2str_(char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod);
static bool argv2str(char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod);
static bool perm_str_to_chmod_cmd(const char* ptr, char strchmod[CHMODSZ]);
static bool test_perms_(const mode_t* perms, const mode_t perm,const char* strperm);
static bool test_perms(const mode_t perm,const char strperm[FPERMSZ]);
static bool test_filetype(const mode_t modetype, const char type);
static bool check_perms(const int dirFd, const int fileFd, const char* filepath, const char type, const short nlinks, const char strperm[FPERMSZ],
			const short uid, const short gid);
#ifdef USE_PAM
static void show_pam_error(pam_handle_t *const pamh, const int errnum);
static bool set_pam_timeout(void);
//#else
//#define pam_handle_t int
//static bool auth_user(void);
#endif
static int auth_user(struct pamdata *const pampst);
static bool snprintf_managed(char *str, const int size, const char *const format, const char *const value);
static bool set_envvar(char const envvarName[MAX_PATH], const char *const formatString, const char *const value);
static bool set_utmp(char name[FIELDSZ], pid_t child_sid, const char* ttyNumber);
//externs
extern bool vsnprintf_managed(char *str, const int size, const char *const format, ...);
extern void vwritelog(const char *const template, ...);//issue %m for getting strerro(errno)
extern char* getpass2(const char *const prompt);

#ifdef TESTUNIT
static bool testunit(void);
//helpers
static void intprint(const char str[], const int strsz);
static void printArgv(char* *const prog);

/*
 *  intprint: print chars as int ('\t'==9 && '\0'==0 && '\f'==10)
 */
static void intprint(const char str[], const int strsz) {
    char buf[3]="00";
    for (int i=0;i<=strsz;i++){
      sprintf(buf,"%d",str[i]);
      writelog(buf);
    }
}

/*
 *  printArgv: print strarrays from argv one line each
 */
static void printArgv(char* *const prog) {
  unsigned short i=0;
  while (prog[i]!=NULL) {
    writelog(prog[i++]);
  }
}
#endif

/*
 * msg to syslog
 */
static void ewritelog(const char *const msg) {
#ifdef USE_SYSLOG
  //man 3 syslog
  openlog(NULL,LOG_ODELAY,LOG_DAEMON);
  syslog(LOG_CRIT,"%s: %m",msg);
  closelog();
#else
  vwritelog("%s: %m\n",msg);
#endif
}
static void writelog(const char *const msg) {
#ifdef USE_SYSLOG
  openlog(NULL,LOG_ODELAY,LOG_DAEMON);
  syslog(LOG_CRIT,"%s",msg);
  closelog();
#else
  tmpsyslog(msg);
#endif
}

#ifndef USE_SYSLOG
static void tmpsyslog(const char *const msg) {
  int fd=open(LOGFILE_PATH, O_CREAT | O_APPEND | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO );
  if (fd!=-1) {
    dprintf(fd,"xlogin: %s\n",msg);
    close(fd);
  }
}
#endif

/*
 * set_uid_gid: setgid and setuid of process
 */
static bool set_uid_gid(const char *const username, const uid_t uid, const gid_t gid) {
  //const gid_t suppGroups[]={ gid };
  const uid_t current_uid=getuid();
  const gid_t current_gid=getgid();

  if (current_uid==uid && current_gid==gid) {
    //fprintf(stderr,"Inneccesary drop of privileges\n");
    //writelog("Inneccesary drop of privileges");
    return true; //nothing to do
  }
  if (current_gid!=gid) {
    //root belongs to many groups and want to cleanup that
    if (setgroups(0, NULL)!=0){//clear supplementary groups
      //if (setgroups(0, suppGroups)!=0){
      //fprintf(stderr,"Error clearing supplementary groups (%d)\n",errno);
      ewritelog("Error clearing supplementary groups");
      return false;
    }
    //load supplementary groups for user
    if (username!=NULL && initgroups(username,gid)!=0){
      ewritelog("Failed loading supplementary groups for user");
      return false;
    }
    if (setgid(gid)!=0) {
      //fprintf(stderr,"Error changind gid (%d)\n",errno);
      ewritelog("Error changind gid");
      return false;
    }
  }
  if (current_uid!=uid) {
    if (setuid(uid)!=0) {
      //fprintf(stderr,"Error changind uid (%d)\n",errno);
      ewritelog("Error changind uid");
      return false;
    }
  }
  return true;
}

/*
 * nspopen: no shell popen
 */
static FILE* nspopen(char *const prog[], const char *const mode) {//mode: 'r','w':: solo la uso como 'r'
  int fd[2];//0:read end, 1:write end
  if (pipe(fd)==-1){//==0 ok
    ewritelog("Failed to open pipe");
    return NULL;
  }
  const pid_t child_pid=fork();
  if ( child_pid < 0 ){
    ewritelog("Failed to fork nspopen process");
    return NULL;
  }
  else if (child_pid==0){//child
    if (close(fd[0])==-1){//close read end
      ewritelog("Failed to close pipe read end");
      _exit(EXIT_FAILURE);
    }
    if (dup2(fd[1],STDOUT_FILENO)==-1){//redirect stdout to pipe write end
      ewritelog("Failed to close stdout and clone pipe write end");
      _exit(EXIT_FAILURE);
    }
    //char *const prog[]={progName,'\0'};
    execvp(prog[0],prog);
    ewritelog("Failed to exec child program");
    _exit(EXIT_FAILURE);
  }
  //parent
  if (close(fd[1])==-1){//close write end of pipe
    ewritelog("Failed to close pipe write end");
    return NULL;
  }
  FILE* fp=fdopen(fd[0],mode);
  if ( fp == NULL){
    ewritelog("Failed to get pipe stream");
    return NULL;
  }
  return fp;//open read end for reading if mode=='r'
}

/*
 * nspclose: no shell pclose
 */
static int nspclose(FILE* fp) {
  //pid_t child_pid=-1; //any childs
  int status=EXIT_FAILURE;
  //if (waitpid(-1,&status,0)==child_pid && WIFEXITED(status)){
  if (fclose(fp)!=0) {
    ewritelog("Failed to close pipe stream");
    fp=NULL;
    return -1;
  }
  fp=NULL;
  if (waitpid(-1,&status,0)!=-1 && WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
}

/*
 * run_mcookie: get cookie from mcookie, and fine tunning MCOOKIE_SZ constant
 */
static bool run_mcookie(char cookie[MCOOKIE_SZ]) {
  const int cookie_sz=MCOOKIE_SZ;
  char tmpcookie[MCOOKIE_SZ+1];//buffer for checking we got complete cookie
  memset(tmpcookie,0,cookie_sz+1);
  tmpcookie[cookie_sz]='\t';//flag, must be keep (warning: this array not null terminated at its end, but before)
  tmpcookie[cookie_sz-1]='\t';//flag, gets replaced with '\0'
  int status=1;
  FILE *fp=NULL;
  char *const prog[]={"mcookie",'\0'};
  fp= nspopen(prog,"r");
  if (fp == NULL){
    ewritelog("Failed to run mcookie");
    return false;
  }
  if (fgets(tmpcookie,cookie_sz+1,fp)==NULL){
    ewritelog("Failed to read mcookie output or other error");
    nspclose(fp);
    fp=NULL;
    return false;
  }
  status=nspclose(fp);
  fp=NULL;
  if (status!=EXIT_SUCCESS){//!=0
    ewritelog("Failed to complete pclose for mcookie task, child error");
    return false;
  }
  {//checks
    //print cookie chars as int ('\t'==9 && '\0'==0)
    //char buf[3];
    //for (int i=0;i<=cookie_sz;i++){
    //sprintf(buf,"%d",tmpcookie[i]);
    //writelog(buf);
    //}
    if (tmpcookie[cookie_sz]!='\t'){//xauth failed
      ewritelog("Failed getting complete cookie, make more room to MCOOKIE_SZ constant");
      writelog(tmpcookie);
      return false;
    }
    if (tmpcookie[cookie_sz-1]!='\0'){
      writelog("Cookie buffer for mcookie too big, lower MCOOKIE_SZ constant");
      return false;
    }
    const int result=snprintf(cookie,cookie_sz,"%s",tmpcookie);//size ckechs have been done early
    strzero(tmpcookie);
    if (result<0){
      ewritelog("Failed setting cookie buffer. snprintf error");
      return false;
    }
    //writelog(tmpcookie);
    //writelog(cookie);
  }
  return true;
}

/*
 * has_shell: check if we have access to sh
 */
static bool has_shell(void) {
  if (access(user.shell,(R_OK | X_OK))!=0) {
    //writelog("We have not shell"); //or other error!
    return false;
  }
  //writelog("We have shell");
  return true;
}

/*
 * call xauth and create mcookie on user's home
 */
static bool setup_xauth(char authfile[AUTHFILE_SZ]) {
  //crear mcookie usando xauth
  //inicializar authfile en el HOME del user (no dentro del fork porque no comparte variables con main, tiene una copia)
  if (!snprintf_managed(authfile,AUTHFILE_SZ,"%s/.Xauthority",user.home))
    return false;

  //fork before drop priv
  const pid_t child_pid=fork();
  if ( child_pid < 0 ){
    //fprintf(stderr,"Failed to fork xauth process\n");
    ewritelog("Failed to fork xauth process");
    return false;
  }
  else if (child_pid==0) {//child

    if (!set_uid_gid(NULL,user.uid,user.gid)){//fix user
      writelog("Failed dropping privileges for xauth");
      _exit(EXIT_FAILURE);
    }
    const bool hasShell=has_shell(); //test if we have access to sh
    if (hasShell) {
      //setuidgid ${USER} xauth -f ${authfile} -q add :0 . `mcookie`;
      char xauthline[MAX_PATH];
      if (!snprintf_managed(xauthline,MAX_PATH,"xauth -f %s -q add :0 . `mcookie`",authfile)) {
	writelog("xauth line too large (increase MAX_PATH) or snprintf error");
	_exit(EXIT_FAILURE);
      }

      wordexp_t p;
      const int err=wordexp(xauthline, &p, 0);
      if ( err !=0 ) {
	vwritelog("Failed executing xauth with wordexp (wordexp error: %d): %m",err);
	_exit(EXIT_FAILURE);
      }
      char* *const prog = p.we_wordv;
      //printArgv(prog);
      execvp(prog[0],prog);
      wordfree(&p);
    } else {
      char cookie[MCOOKIE_SZ];
      if (!run_mcookie(cookie)){
	//fprintf(stderr,"Failed to get mcookie result\n");
	writelog("Failed to get mcookie result");
	_exit(EXIT_FAILURE);
      }
      char *const prog[]={"xauth","-f",authfile,"-q","add",":0",".",cookie,'\0'};
      execvp(prog[0],prog);
    }
    ewritelog("Failed to exec xauth");
    _exit(EXIT_FAILURE);
  }
  //parent
  int status;
  if (waitpid(child_pid,&status,0)==child_pid && WIFEXITED(status)){
    if (WEXITSTATUS(status)==EXIT_SUCCESS){
      return true;
    } else {
      writelog("Run of xauth failed");
    }
  }
  return false;
}

/*
 * sigIgnore - dummy for catch SIGUSR1
 */
static void sigIgnore(const int sig) {
  //writelog("xlogin signaled");
  return;
}

/*
 * sigAbort - handler para fallar si llega el timeout
 */
static void sigAbort(const int sig) {
    writelog("Timeout waiting xserver ready status");
    exit(EXIT_FAILURE);
  }

/*
 * start_xserver - start X server doing xinit work as root user
 */
static pid_t start_xserver(char *const default_vt) {
  //const char authfile[]="/home/${USER}/.Xauthority";
  char authfile[AUTHFILE_SZ];
  memset(authfile,0,AUTHFILE_SZ);
  char default_xserver[]=DEFAULT_XSERVER;
  /*
  char default_vt[L_ctermid];
  char msg[ERR_MSG];
  snprintf(msg,ERR_MSG,"tty: %s",ctermid(NULL)); //da /dev/tty
  writelog(msg);
  */
  //setup xauth record, making mcookie on homedir
  if (!setup_xauth(authfile)) {//puede que tenga que pasarle username
    //fprintf(stderr,"Failed to setup xauth record\n");
    writelog("Failed to setup xauth record");
    exit(EXIT_FAILURE);
  }

  //pwd no debe estar en dir mounted o no podre desmontar mientras el daemon corra
  if (chdir("/")!=0) {
    ewritelog("Failed to chdir to /");
  }

  const pid_t pid=fork();
  if ( pid < 0 ) {
    //fprintf(stderr,"Failed to fork xserver process\n");
    writelog("Failed to fork xserver process");
    exit(EXIT_FAILURE);
  }
  else if (pid==0) {//child
    if (signal(SIGUSR1, SIG_IGN)==SIG_ERR) {//make server signalling parent with SIGUSR1 when ready (taken from xinit src)
      writelog("Failed to setup xserver sigusr1 signaler");
      _exit(EXIT_FAILURE);
    }

    //this don't change socket perms
    //umask(S_IROTH | S_IWOTH | S_IXOTH);//007

    char *const display=":0";//el parametro de Xorg fd permite que sea el quien defina displayNum
    //vt autoselect to 'current+1'
    //char *const xserver[]={default_xserver,display,"vt07","-retro","-nolisten","tcp","-nolisten","local","-auth",authfile,'\0'};
    //char *const xserver[]={default_xserver,display,"vt08","vt07","-retro","-nolisten","tcp","-nolisten","local","-auth",authfile,'\0'}; //works
    //char *const xserver[]={default_xserver,display,default_vt,"-retro","-nolisten","tcp","-nolisten","local","-auth",authfile,'\0'};
    char *const xserver[]={default_xserver,display,default_vt,"-novtswitch","-nolisten","tcp","-nolisten","local","-auth",authfile,'\0'};
    //char *const xserver[]={default_xserver,display,default_vt,"-nolisten","tcp","-nolisten","local","-auth",authfile,'\0'};
    execvp(xserver[0],xserver);
    ewritelog("Failed to exec xserver");
  }
  //parent
  //setup catcher for SIGUSR1, xserver send us when ready
  if (signal(SIGUSR1,sigIgnore)==SIG_ERR) {
    writelog("Failed to setup xserver sigusr1 catcher");
    exit(EXIT_FAILURE);
  }
  //wait XSERVER_WAIT_TIMEOUT to xserver ready
  if (signal(SIGALRM,sigAbort)==SIG_ERR) {
    writelog("Failed to setup xserver timeout catcher");
    exit(EXIT_FAILURE);
  }
  //esperar y finalizar si no llega sigusr1
  //waitpid(pid,NULL,0); //espera indefinidamente
  alarm(XSERVER_WAIT_TIMEOUT);
  pause();//wait sigusr1 from xserver
  alarm(0);
  //for display :0 (ver opcion fd de Xorg)
  //const char socket[]="/tmp/.X11-unix/X0";
  //const char socket[]= _PATH_TMP ".X11-unix/X0";//BUG corregir si DISPLAY esta definida?
  const char socket[]= XSOCKETDIR "X0";//BUG corregir si DISPLAY esta definida?
  const char socketdir[]= XSOCKETDIR;
  //while [ ! -e ${SOCKET} ];do sleep 1s;done

  //unusables 'no such file or dir'
  //const int socketFd = open(socket,O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RDONLY);
  //const int socketFd = open(socket,O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_PATH);//??
  const int socketdirFd = open(socketdir, O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RDONLY);
  if (socketdirFd==-1) {
    vwritelog("Failed to open file descriptor to xserver socket directory '%s' : %m",socketdir);
    goto cleanupx;
  }

  //check socket exists
  //if (access(socket,F_OK)!=0) {
  if (faccessat(socketdirFd, socket, F_OK, AT_SYMLINK_NOFOLLOW)!=0) {
    ewritelog("Failed to access socket");
    goto cleanup;
  }

  {//check perms of initial socket (root:root) no hijacking!
    //perm checks
    if (!check_perms(socketdirFd, -1, socket, 's', 1, "---rw#rw#r##", 0, 0)) {//0777
      writelog("Incorrect xserver socket permissions");
      goto cleanup;
    }
    //check parents
    if (!check_parents("Insecure parent: %s. Minimal requirements are root:root o+t","--xr#xr#x###",socket)) {
      vwritelog("Insecure parents found. Parent dirs of %s must be root:root owned and 'other' with sticky bit set",socket);
      goto cleanup;
    }
  }
  //quiero srwxrwx---
  //chmod o-rwx ${SOCKET}
  //  umask(S_IRWXO);
  //if (chmod(socket,S_IRWXU | S_IRWXG)!=0) {
  //if (fchmod(socketFd, S_IRWXU | S_IRWXG)!=0) {
    //fprintf(stderr,"Failed to chmod xserver socket\n");
#ifdef SECURE_FCHMODAT
  if (fchmodat(socketdirFd, socket, S_IRWXU | S_IRWXG, AT_SYMLINK_NOFOLLOW)!=0) {
    writelog("Failed to chmod xserver socket");
    goto cleanup;
  }
#else
  if (fchmodat(socketdirFd, socket, S_IRWXU | S_IRWXG, 0)!=0) {
    writelog("Failed to chmod xserver socket");
    goto cleanup;
  }
#endif
  //chgrp ${USER} ${SOCKET}
  //if (lchown(socket,-1,user.gid)!=0) {//-1 keeps uid (==0 hopes)
  //if (fchown(socketFd,-1,user.gid)!=0) {//-1 keeps uid (==0 hopes)
  if (fchownat(socketdirFd, socket, -1, user.gid, AT_SYMLINK_NOFOLLOW)!=0) {//-1 keeps uid (==0 hopes)
    //fprintf(stderr,"Failed to chown xserver socket\n");
    writelog("Failed to chown xserver socket");
    goto cleanup;
  }

  if (close(socketdirFd)!=0) {
    ewritelog("Failed to close xserver socket file descriptor");
    goto cleanupx;
  }

  return pid;

 cleanup:
  if (close(socketdirFd)!=0) {
    ewritelog("Failed to close xserver socket file descriptor");
  }
 cleanupx:
  if (kill(pid, SIGINT)!=0) {//kill X or blank screen appears
    ewritelog("Failed to kill xserver");
  }
  return ((pid_t) -1);
}

/*
 * snprintf_managed: helper setting str reading size from value and fail if value's size greater than size param
 */
static bool snprintf_managed(char *str, const int size, const char *const format, const char *const value) {
  if (size==0) {
    writelog("snprintf_managed: error, size can't be 0");
    return false;
  }
  const int result=snprintf(str,size,format,value);
  if (result>=size){//size insuficent for value
    ewritelog("snprintf_managed: Failed to set char, insuficient size");
    return false;
  }
  if (result<0){//snprintf error
    ewritelog("snprintf_managed: Failed to set char because snprintf error");
    return false;
  }
  return true;
}

/*
 * set_envvar: helper setting env para variables de path sobreescribiendo el env
 */
static bool set_envvar(const char *const envvarName, const char *const format, const char *const value) {
  char envvar[MAX_PATH];
  memset(envvar,0,MAX_PATH);
  //set str value
  if (!snprintf_managed(envvar,MAX_PATH,format,value)) {
    return false;
  }
  //try setting value overwriting
  if (setenv(envvarName,envvar,1)!=0){
    vwritelog("Failed to set '%s' environment variable: %m",envvarName);
    return false;
  }
  return true;
}

/*
 * replace_unprintables: quitar el final del str los posibles '\n' '\f' con '\0' ( man ascii(7) )
 */
/*
static void replace_unprintables(char sessionbin[]) {
  const int sz=strlen(sessionbin);
  if( sessionbin[sz-1]=='\n' || sessionbin[sz-1]=='\r'){
    sessionbin[sz-1]='\0';
  }
  if( sessionbin[sz-2]=='\n' || sessionbin[sz-2]=='\r'){
    sessionbin[sz-2]='\0';
  }
  unsigned short i=sz-1;
  while ((i>=0) && (sessionbin[i]==' ')) {
    sessionbin[i]='\0';
    i--;
  }
}
*/

/*
 * trim_ending_spaces: quitar del final del str los posibles spaces
 */
/*
static void trim_ending_spaces(char *const sessionbin) {
  const int sz=strlen(sessionbin);
  unsigned short i=sz-1;
  while ((i>=0) && (sessionbin[i]==' ')) {
    sessionbin[i--]='\0';
  }
}
*/

/*
 * trim_spaces: delete ending spaces (NULL replaced) and hide starting spaces (move returned pointer from start of char[])
 */
static void trim_spaces(char *const sessionbin, char** outcharptr) {
  const int sz=strlen(sessionbin);
  if (sz>0) {
    //fill end
    unsigned short i=sz-1;
    while ((i>=0) && (sessionbin[i]==' ')) {
      sessionbin[i--]='\0';
    }
    //move start
    char* outchar=sessionbin;
    i=0;
    while ( (i<=sz) && (sessionbin[i]==' ') ) {
      outchar++;
      i++;
    }
    *outcharptr=outchar;
  } else {
    *outcharptr=sessionbin;
  }
}

/*
 * splitcount: calcular el numero de veces que strtok hace split sobre un string (se supone que es tail recursive)
 */
// no marco con const porque strtok modifica el array de entrada
static int splitcount(char arr[],const char delim[]) {
  if (strtok(arr,delim)==NULL){//no hay coincidencias
    return 1;//como minimo hay un token
  } else {
    return 1+splitcount(NULL,delim);
  }
}

/*
 * splitasign: make splitting of arr using delim and store each part to a slot in prog. Changes arr in  strok call.
 *  first param is always 0
 *  asignar strlen(prog) veces strtok de arr usando delim; hace split sobre arr usando delim (se supone que es tail recursive). Cambia arr
 */
static void splitasign(int i, const char delim[], char arr[], char* prog[]) {
  if ( (prog[i]=strtok(arr,delim)) != NULL ) {
    splitasign(++i,delim,NULL,prog);//NULL for reusing arr into strok
  }
}

/*
 * splitstr: convert from char arr[] to argv format splitting with delimiters in delim[].
 *   Changes arr! and arr can't be freed because ptrprog's char[] are references to it.
 *           Desde char array con delimitadores, obtener char** sin delimitadores y splitted en formato argv
 *           ejemplo: "xterm -rv bash" resulta en { "xterm", "-rv", "bash" , NULL}; hay que hacer free de *ptrprog
 *           arr no puede ser const porque se modifica en la funcion, y no puedo duplicarlo dentro porque el argv toma los arrays de arr. Tampoco liberar arr.
 */
static bool splitstr(const char delim[], char arr[], char*** ptrprog) {
  //number of splits; pass copy to arr because gets changed
  //get size of arr on split
  char *const cparr=strdup(arr);
  if ( cparr == NULL ){
    ewritelog("Failed to strdup array for getting size of split");
    *ptrprog=NULL;
    return false;
  }
  const int n=splitcount(cparr,delim);
  free(cparr);
  if (n<2){
    writelog("Unexpected size of line");//{ ( first_line_non_commented_of_xloginrc ) ,NULL}
    *ptrprog=NULL;
    return false;
  }

  //char *tmp[n];
  //char *tmp[3];
  //char **tmp=(char**) malloc(n*sizeof(char*));
  char* *const prog=(char**) malloc((n*sizeof(char*)));
  //*prog=(char*) malloc((n*sizeof(char*)));
  if (prog==NULL){
    ewritelog("Failed malloc from splitstr");
    return false;
  }
  //char** tmp=prog;
  /*
    tmp[0]="xterm";
    tmp[1]="-rv";
    tmp[2]=NULL;
  */
  //prog[n-1]='\0';
  /*
  char *const cparr=strdup(arr);
  if ( cparr == NULL ){
    ewritelog("Failed to strdup array for getting split");
    *ptrprog=NULL;
    return false;
  }
  splitasign(0,delim,cparr,prog);
  free(cparr);//al hacer esto, elimino los strings (son referencias a los que se mandan con cparr)
  */
  splitasign(0,delim,arr,prog);//keep arr because prog has refs to it, and arr gets changed by strtok
  //assertion(prog!=NULL)
  if ( prog[0]==NULL ){
    writelog("Unexpected NULL string of line");
    *ptrprog=NULL;
    return false;
  }
  /*
    vwritelog("n: %d",n);
    writelog("tosplit:");
    writelog(arr);
    writelog("result:");
    //print array tmp
    for (int i=0;i<n;i++){
    writelog("<<<");
    writelog(prog[i]);
    writelog(">>>; num strings:");
    if (prog[i]!=NULL){
    intprint(prog[i],strlen(prog[i]));
    }
    writelog("NEXT");
    }
  */
  *ptrprog=prog;
  return true;
}

#ifdef USE_PAM
/*
 * exists_pamconf: return xlogin pam's file with path build from template and filename, and test if exists/have correct permissions
 */
static bool exists_pamconfig(void) {
  const char *const permMsg="Permissions of xlogin pam file must be owned for root:root and 'other' readable only";
  const char *const perm="---rw-r--r--";
  char pamconfig[MAX_PATH];
  if (!build_and_test_path("%s", CONFIG_PAM, permMsg, 'r', perm, pamconfig)) {
    ewritelog("Error finding PAM's xlogin config file '" CONFIG_PAM "'");
    return false;
  }
  return true;
}
#endif

/*
 * exists_xloginrc: return xloginrc with path build from template and filename, and test if exists/have correct permissions
 *  User's xloginrc takes precedence over system xloginrc
 */
static bool exists_xloginrc(char xloginrc[MAX_PATH]) {
  const char *const permMsg="Permissions of xloginrc files must be owned for root:root and 'other' readable only";
  const char *const perm="---rw-r--r--";
  //podria hacer un rc con opciones para usuario y hacer que la opcion del script de usuario se validase contra esa lista, entonces el fichero podria ser own por el user
  //implementado en esta misma funcion
  //if (!build_and_test_path("%s/.xloginrc", user.home, permMsg, 'r', perm, xloginrc)) {//disable user sript support, needed something more secure
    if (!build_and_test_path("%s", XLOGINDIR "/xloginrc", permMsg, 'r', perm, xloginrc)) {
      return false;
    }
    //}
  return true;
}

/*
 * exists_path{xloginrc,proc}
 * build_test_path: return filepath with path build from template and filename, and test if exists xloginrc file in path
 *                  permMsg es el mensaje de error si los permisos fallan, y perm es el permiso en str no permitido
 */
static bool build_and_test_path(const char *const template, const char *const filename, const char permMsg[], const char filetype, const char perm[],
				char filepath[MAX_PATH]) {
  //build path
  if (!snprintf_managed(filepath,MAX_PATH,template,filename)) {
    vwritelog("Path to %s too long or other error",filename);
    _exit(EXIT_FAILURE);
  }
  //test if filepath exists and its readable
  if (access(filepath,R_OK)!=0) {//BUG refinar para ver cuando se produce error??
    //ewritelog("Hasn't got perms, file missing or other error");
    return false;
  } else {
    //perm checks
    short hardlinks=1;
    if (filetype=='d') {
      hardlinks=-1;//disable test for dirs
    }
    if (!check_perms(-1,-1,filepath,filetype,hardlinks,perm,0,0)) {
      writelog(permMsg);
      _exit(EXIT_FAILURE);
    }
    //check parents
    if (!check_parents(NULL,NULL,filepath)) {
      vwritelog("Insecure parents found. Parent dirs of %s must be root:root owned and 'other' no writeable at least",filepath);
      _exit(EXIT_FAILURE);
    }
    return true;
  }
}

/*
 * valid_not_commented_or_null: validate line from xloginrc/sessionrc. Is valid if neither commented nor empty
 */
static bool valid_not_commented_or_null_line(const char sessionbin[MAX_PATH]) {
  const char str=sessionbin[0];
  if ( (str=='#') || (str=='\0') || (str=='\r') ) {
    return false;
  }
  return true;
}

/*
 * cmd2buf: helper for storing pointer value to buffer (ensure buffer length, trim ending ans starting spaces and secure copy to buffer)
 */
static bool cmd2buf(const bool eof, char sessionbintmp[MAX_PATH], char sessionbin[MAX_PATH]) {
  char* sessionbintmp2=NULL;
  { //check MAX_PATH not rebased
    const unsigned short maxpath=MAX_PATH;
    const unsigned short i_newline=strlen(sessionbintmp)-1;
    if (i_newline<0) {
      writelog("String too short, must contain at least newline plus null");
      return false;
    }
    if (sessionbintmp[i_newline]!='\n') {//we require newline for each line read
      if (eof) {//eof => we miss last line
	if (i_newline+2==maxpath) {//MAX_PATH could have been rebased 'i_newline+1==MAX_PATH-1'
	  writelog("Error: line too long in config file. MAX_PATH could have been rebased. Patch an increased MAX_PATH #define if required and recompile this package. Alternatively include a commented line at end of file for inprobed buffer size check");
	  return false;
	  //} else {
	  //writelog("Error in config file. Check if: you have removed required last commented line or you have NULLs interleaved in text.");
	}
      } else {//!eof => MAX_PATH rebased OR NULL interleaved in text
	writelog("Error in config file: NULLs interleaved in text line (please remove then) or line too long (MAX_PATH rebased. Patch an increased MAX_PATH #define if required and recompile this package)");
	return false;
      }
    } else {
      //trim newline
      sessionbintmp[i_newline]='\0';
    }
  }
  trim_spaces(sessionbintmp,&sessionbintmp2);
  if (!snprintf_managed(sessionbin,MAX_PATH, "%s", sessionbintmp2)) {
    writelog("Error filling buffer from trimmed array");
    return false;
  }
  return true;
}

/*
 * read_valid_line_from_file: read line neither commented nor empty
 *  fp_ptr is a stream pointer (FILE**), filename is for errors references to file opened in stream and validate is a function ptr which validate data gathered
 */
static bool read_valid_line_from_file(FILE* *const fp_ptr, const char *const filename, bool (*validate)(const char *const), char line[MAX_PATH]) {
  char linetmp[MAX_PATH];//dont use maxpath here! or will trigger dynamic array
  const short maxpath=MAX_PATH;
  memset(linetmp,0,maxpath);
  FILE* fp=*fp_ptr;
  bool eof=false;
  if (fp==NULL) { //invalid case
    vwritelog("Unexpected null file pointer reading %s",filename);
    return false;
  }
  //read first valid line (neither commented nor empty)
  do {
    if (fgets(linetmp,maxpath,fp)==NULL) {//error or read with no chars and EOF
      if (feof(fp)==0) {//error
	vwritelog("Failed to read %s values: %m",filename);
	if (fclose(fp)!=0) {
	  vwritelog("Failed to close %s file pointer: %m",filename);
	}
	*fp_ptr=NULL; //flag meaning fp was closed because error
      //} else {//eof and no chars
	//vwritelog("Failed to read %s values: empty value in last line",filename);
	//have no chars, couldn't overflow buffer and its EOF, everything ok
      }
      return false;
    }
    if (feof(fp)!=0) {//last line and have chars
      eof=true;
    }
    //vwritelog("readed: '%s'",linetmp);
    if (!cmd2buf(eof,linetmp,line)) {//fill line with values without spaces and keep pointer at start
      vwritelog("Error formatting string array in %s",filename);
      return false;
    }
    //writelog(line);
  } while( !( (*validate) (line) ) );//roll again if not validated
  return true;
}

/*
 * valid_yama_line
 */
static bool valid_yama_line(const char str[MAX_PATH]) {
  if (strlen(str)!=1) {
    return false;
  }
  return true;
}

/*
 * valid_proc_line: filter proc line
 */
static bool valid_proc_line(const char str[MAX_PATH]) {
  char **argvline=NULL;
  bool result=false;
  //duplicar el array
  char *const cpstr=strdup(str);
  if ( cpstr == NULL ){
    ewritelog("Failed to strdup array for getting split while validating proc line");
    exit(EXIT_FAILURE);
  }
  if (!splitstr(" \n", cpstr, &argvline)) {
    writelog("Error with splitstr while finding valid proc line");
    exit(EXIT_FAILURE);
  }
  //proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0
  if (strcmp("/proc",argvline[1])==0) {
    result=true;
  }
  free(argvline);argvline=NULL;
  free(cpstr);
  return result;
}

/*
 * action_proc_line
 * profile: run action for first found or fail
 */
static bool action_proc_line(bool *const success, const bool hasShell, char line[MAX_PATH]) {
  bool eof=true;//get out of while and proceed to close file
  if (!(*success)) {//eof
    writelog("Error getting valid /proc line from file " PROC_MOUNTS);
  } else {
    //work duplicated with valid_proc_line for proc line only
    char **argvline=NULL;
    if (!splitstr(" \n", line, &argvline)) {//destroys line array!
      writelog("Error with splitstr while splitting");
      return false;
    }
    //proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0
    const bool secure=strstr(argvline[3],HIDEPID_INVISIBLE)==NULL? false:true;
    free(argvline);argvline=NULL;
    if (!secure) {
      writelog("/proc must be mounted with hidepid=2 (invisible) for protecting magic cookie from stealing");
      return false;
    }
  }
  return eof;
}

/*
 * action_yama_line
 * profile: run action for first found or fail
 */
static bool action_yama_line(bool *const success, const bool hasShell, char line[MAX_PATH]) {
  bool eof=true;//get out of while and proceed to close file
  if (!(*success)) {//eof
    writelog("Couln't find valid line in " PROC_YAMA);
  } else {
    //valid value, lets compare with profile
    const char yamaprofile=YAMA_PROFILE;
    const char yamavalue=line[0];
    if (yamavalue < yamaprofile) {
      vwritelog("Yama profile too permissive '%c', set it to '%c'", yamavalue, yamaprofile);
      *success=false;
    }
  }
  return eof;
}

/*
 * exists_proc: return procdir with path build from template and filename, and test if exists/have correct permissions
 */
static bool exists_proc(char procdir[MAX_PATH]) {
  const char *const permMsg="Permissions of " PROC_MOUNTS " file must be owned for root:root and 'other' readable only";
  const char *const perm="---r--r--r--";
  return build_and_test_path("%s", PROC_MOUNTS, permMsg, 'r', perm, procdir);
}

/*
 *  test_fstype: see man statfs: information about a mounted filesystem type
 */
static bool validate_fstype(const char *const path, __fsword_t fstype) {
  struct statfs buf;
  memset(&buf,0,sizeof(buf));
  if (statfs(path,&buf)!=0) {
    vwritelog("Error getting fs info for path %s (%m)",path);
    return false;
  }
  if (buf.f_type!=fstype) {
    vwritelog("Incorrect fstype for path %s",path);
    return false;
  }
  return true;
}

/*
 * is_proc_secure: check if proc is mounted hidepid=invisible
 */
static bool is_proc_secure(void) {
  char procdir[MAX_PATH];
  //test if exists and build path in buffer procdir
  if (!exists_proc(procdir)) {
    return true;
  } else {//proc exists
    char line[MAX_PATH];
    {//check proc mount point
      //check fstype
      if (!validate_fstype(PROC_MOUNTS, PROC_SUPER_MAGIC)) {
	writelog("Failed to validate proc fs type");
	return false;
      }
      //get proc line from PROC_MOUNTS
      if (!got_valid_line(false, procdir, valid_proc_line, action_proc_line, line)) {
	//writelog("Unable to find valid proc line");
	return false;
      }
    }
    {//check yama support active
      const char proc_yama[]=PROC_YAMA;
      if (!got_valid_line(false, proc_yama, valid_yama_line, action_yama_line, line)) {
	//writelog("Unable to find valid proc line");
	return false;
      }
    }
    return true;
  }
}

/*
 * fork_prog_: fork no wait process prog
 */
static void fork_prog_(char *const prog[], pid_t* child_pid) {
  /*
  //create handlers for save and restoring default handler
  struct sigaction oldHandler,newHandler;
  memset(&newHandler,0,sizeof(newHandler));
  if (sigemptyset(&newHandler.sa_mask)!=0) {
    ewritelog("Failed to set mask to empty set");
    exit(EXIT_FAILURE);
  }
  newHandler.sa_handler=SIG_IGN;
  //ignore SIGCHLD for no defuncts
  if (sigaction(SIGCHLD,&newHandler,&oldHandler)!=0) {
    ewritelog("Failed to set signal action");
    exit(EXIT_FAILURE);
  }
  //signal(SIGCHLD,SIG_IGN);//no defuncts
  */
  const pid_t pid=fork();
  if ( pid < 0 ) {
    writelog("Failed to fork process");
    exit(EXIT_FAILURE);
  }
  else if (pid==0){//child
    execvp(prog[0],prog);
    ewritelog("Failed to exec child process");
    _exit(EXIT_FAILURE);
  }
  //parent
  if (child_pid!=NULL) {
    *child_pid=pid;
  }
  /*
  //restore original handler
  if (sigaction(SIGCHLD,&oldHandler,NULL)!=0) {
    ewritelog("Failed to restore signal action");
    exit(EXIT_FAILURE);
  }
  */
}

/*
 * fork_prog: fork with options
 */
static void fork_prog(const bool hasShell, char sessionbin[MAX_PATH], pid_t* child_pid) {
  //action with values
  if (hasShell) {
    wordexp_t p;
    const int err=wordexp(sessionbin, &p, 0);
    if ( err !=0 ) {//wordexp performs better and catch quotes (without shell), and backticks, dollar (with shell)
      vwritelog("Failed executing with wordexp (shell available?). Wordexp error code: %d",err);
      _exit(EXIT_FAILURE);
    }
    //printArgv(p.we_wordv);
    fork_prog_(p.we_wordv, child_pid);//argv format
    //free resources
    wordfree(&p);
  } else {
    char **session=NULL;
    //BUG splitstr fails with quoted strings
    if (!splitstr(" \n\r", sessionbin, &session)) {//format session array for exec
      writelog("splitstr failed");
      _exit(EXIT_FAILURE);
    }
    //printArgv(session);
    fork_prog_(session, child_pid);
    //free resources
    free(session);
    session=NULL;
  }
}

/*
 * action_first_line
 * profile: run action for first found or fail
 */
static bool action_first_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]) {
  bool eof=true;//get out of while and proceed to close file
  if (!(*success)) {//eof
    writelog("Error getting valid line from file xloginrc");
  }
  return eof;
}

/*
 * action_login_line: do login actions. Run cmds while success to exec line (starting with '*'), cmd returned in sessionbin
 * profile: run action for first found or fail
 */
static bool action_login_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]) {
  bool eof=false;
  if (!(*success)) {//eof
    writelog("Error getting valid line from sessionrc file. Did you forgot adding '*' to last executed line?");
    eof=true;//get out of while and proceed to close file if remains open
  } else {
    if (sessionbin[0]!='*') {//dont match line to fork
      fork_prog(hasShell,sessionbin,NULL);
    } else { //line to fork in main
      eof=true;
    }
  }
  return eof;
}

/*
 * action_logout_line: do login actions. Run cmds while success to end of file
 * profile: run actions for all found to end without failing
 */
static bool action_logout_line(bool *const success, const bool hasShell, char sessionbin[MAX_PATH]) {
  bool eof=false;
  if (!(*success)) {//eof
    *success=true;//ok if we reach eof
    eof=true;//get out of while and proceed to close file if remains open
  } else {
    pid_t child_pid=-1;
    fork_prog(hasShell,sessionbin,&child_pid);
    if (child_pid==-1) {
      writelog("Error gettting child process while stopping session");
    } else {
      //wait stop actions
      if (!waitpid_with_log(child_pid)) {
	ewritelog("Error waiting child process while stopping session");
      }
    }
  }
  return eof;
}

/*
 * got_valid_line: read file sessionrc and store last valid line in sessionbin
 * valid lines choosed with 'validate' function, 'action' function could continue/finish after a successful find and change successful status with more test
 */
static bool got_valid_line(const bool hasShell, const char sessionrc[MAX_PATH], bool (*validate)(const char *const),
			   bool (*action)(bool *const, const bool, char[MAX_PATH]), char line[MAX_PATH]) {//BUG: set MAX_LINE to 'line'?
  bool eof=false;
/*
  if (signal(SIGCHLD,SIG_IGN)==SIG_ERR) {//no defuncts (works)
    ewritelog("Error setting signal handle to ignore child termination");
    return false;
  }
*/
  //open file, make action each line except last, take data last line and close file
  FILE* fp=fopen(sessionrc,"r");
  if (fp==NULL) {
    vwritelog("Error openning '%s' file: %m",sessionrc);
    return false;
  }
  bool success=false;
  //read line by line
  do {
    //read valid line (neither commented nor empty)
    success=read_valid_line_from_file(&fp,sessionrc,(*validate),line);
    if (fp==NULL) {
      vwritelog("Stream error reading '%s'",sessionrc);
      return false;
    }
    eof=(*action)(&success,hasShell,line);
  } while (!eof);

  //close file
  if (fp!=NULL) {
    if (fclose(fp)!=0) {
      fp=NULL;
      vwritelog("Failed to close file pointer to '%s': %m",sessionrc);
      return false;
    }
    fp=NULL;
  }
  return success;
}

/*
 *  include: strings accepting filter. Compares only first chars of pattern string
 */
static bool include(const char* *const patterns,const char *const str) {
  if (patterns==NULL || patterns[0]==NULL) { return false; }
  const unsigned short sz=strlen(patterns[0]);
  return ( (strncmp(patterns[0],str,sz)==0?true:false) || include(patterns+1,str) );
}

#ifndef USE_PAM
/*
 * valid_env_line: validate line from /etc/environment. Is valid if neither commented nor empty and pairs NAME=VALUE
 */
static bool valid_env_line(const char name[MAX_PATH]) {
  {//cleck no comented or null starting line (came space free (ltrimmed, rtrimmed))
    const char str=name[0];
    if ( (str=='#') || (str=='\0') || (str=='\r') ) {
      return false;
    }
  }
  //check is pair
  {
    char* value=strrchr(name,'=');//point to last '=' char
    if (value==NULL) {
      vwritelog("Invalid environment var assignation, missing equal char: '%s'",name);
      return false;//not a pair
    }
    value++;//points to value //if envvar has only 'NAME=' this points to '\0'
    if (*value=='\0') {//dont import vars as 'NAME='
      return false;
    }
  }
  return true;
}

/*
 * action_env_line: parse and register env vars
 * profile: run actions for all found to end without failing
 */
static bool action_env_line(bool *const success, const bool hasShell, char name[MAX_PATH]) {
  bool eof=false;
  if (!(*success)) {//eof
    *success=true;//ok if we reach eof
    eof=true;//get out of while and proceed to close file if remains open
  } else {
    //just checked is valid pair
    /*
    char* name=strdup(line);//needed because we change '=' with '\0'
    if (name==NULL) {
      ewritelog("Error duplicating string");
      *success=false;
      eof=true;
      return eof;
    }
    */
    char* value=strrchr(name,'=');//point to last '=' char
    /*
    if (value==NULL) {
      vwritelog("Invalid environment var assignation, missing equal char: '%s'",line);
      goto failed;//not a pair
    }
    */
    *value='\0';//overwrite '=' with NULL
    value++;//points to value //if envvar has only 'NAME=' this points to '\0'
    /*
    if (*value=='\0') {
      goto cleanup;//empty pair; dont import vars as 'NAME='
      //ignore and no fail
    }
    */
    //excluir envvars que tienen LD* o "ROOTPATH*"
    const char* filter[]={"ROOTPATH","LD",NULL};
    if (!include(filter,name)) {
      //vwritelog("Env var accepted '%s=%s' (sz: %d)",name,value,strlen(name)); //BUG: al descomentar los vwrite, a veces casca (puede que setenv falle tb)
      if (setenv(name,value,0)!=0) {//fix var not overwritting
	vwritelog("Failed setting environment with %s: %m",name);
	*success=false;
	eof=true;
      }
      //} else {
      //vwritelog("Env var rejected '%s=%s' (sz: %d)",name,value,strlen(name));
    }
    //vwritelog("Setting envvar: '%s' = '%s'",name,value);
    //free(name);
  }
  return eof;
}

/*
 * load_env: cargar /etc/environment
 */
static bool load_env(void) {
  char envfilepath[MAX_PATH];
  {
    const char *const permMsg="Permissions of " ENV_FILE " file must be owned for root:root and 'other' readable only";
    const char *const perm="---r#-r#-r--";
    if (!build_and_test_path("%s", ENV_FILE, permMsg, 'r', perm, envfilepath)) {
      writelog("Failed building/testing environment file path");
      return false;
    }
  }
  char line[MAX_PATH];
  if (!got_valid_line(false, envfilepath, valid_env_line, action_env_line, line)) {
    //writelog("Unable to find valid proc line");
    return false;
  }
  return true;
}
#else //USE_PAM
static bool load_pam_env(const struct pamdata *const pampst) {
  //import pam env list
  pam_handle_t *const pamh=pampst->pamh;
  char* *const env=pam_getenvlist(pamh);
  //printArgv(env);
  if (env!=NULL) {
    char** envp=env;
    char* var=NULL;
    const char* filter[]={"ROOTPATH","LD",NULL};
    while ( (var=envp[0]) != NULL ) {
      //filter LD_* y ROOTPATH*
      if (!include(filter,var)) {//get envvar not included in filter
	//if (strncmp("LD",var,2)!=0) {//dont begins with "LD"
	//vwritelog("Accepted environment var '%s'",var);//dont list envvar contents to syslog
	if (getenv(var)==NULL) {//don't overwrite values
	  if (putenv(var)!=0) {//bring here variables defined by pam_systemd (XDG_RUNTIME_DIR, etc)
	    vwritelog("Failed importing environment var '%s': %m",var);
	    return false;
	  }
	}
      } else {
	//vwritelog("Filtered environment var '%s' for safety",var);//dont list envvar contents to syslog
	free(var);//dont free variables included!!
      }
      envp++;
    }
    free(env);
  }
  return true;
}
#endif

/*
 * waitpid_with_log
 */
static bool waitpid_with_log(const pid_t child_pid) {
  int status=EXIT_FAILURE;
  if (waitpid(child_pid,&status,0)==child_pid) {//child returns
    if (!WIFEXITED(status)) {
      writelog("Child session process crashed");//non fatal because happens
    } else{
      if (WEXITSTATUS(status)!=EXIT_SUCCESS) {
	vwritelog("Child session process ended with failure (%d)",WEXITSTATUS(status));
      }
    }
  } else {//failed waiting
    return false;
  }
  return true;
}

/*
 * waitsid_with_log: wait child process group
 */
static bool waitsid_with_log(const pid_t child_sid) {
  pid_t cpid=-1;
  int status=EXIT_FAILURE;
  //man wait(3p)
  //vwritelog("waiting childs pg: %d",child_sid);
  while ( (cpid=waitpid(-child_sid,&status,0)) !=-1 ) {//with child_sid==0 wait childs pg same of parent
    if (!WIFEXITED(status)) {
      vwritelog("Process with pid=%d crashed",cpid);
    } else {
      if (WEXITSTATUS(status)!=EXIT_SUCCESS) {
	vwritelog("Process with pid=%d ended with failure (%d)",cpid,WEXITSTATUS(status));
      }
    }
  }
  if (errno!=ECHILD) {
    return false;
  }
  return true;
}

/*
 * start user session as user
 */
static void start_session(struct pamdata *const pampst) {
#ifndef USE_PAM
  (void) pampst;
#endif

#ifdef USE_PAM
  //drop gid privileges
  if (!set_uid_gid(user.name,0,user.gid)) {//fix user
    writelog("Failed dropping group privileges for session start");
    _exit(EXIT_FAILURE);
  }
  {//pam_setcred
    //pam_setcred must be called here, after drop priv
    //user was authenticated, now setup session
    pam_handle_t *const pamh=pampst->pamh;
    int result=pam_setcred(pamh,PAM_ESTABLISH_CRED);//setting credentials

    /*
      if (result==PAM_SUCCESS) {//create session
      result=pam_open_session(pamh,0);//fails with 'no child process'
      } else {
      show_pam_error(pamh, result, &warned);//from pam_setcred
      }
    */
    if (result!=PAM_SUCCESS) {
      show_pam_error(pamh, result);//from pam_setcred
      //close session
      if (pam_close_session(pamh,0)!=PAM_SUCCESS) {
	writelog("Cleanup failed. PAM function pam_close_session failed");
      }
      //call pam_end on error for cleanup
      if (pam_end(pamh,result)!=PAM_SUCCESS) {
	writelog("Cleanup failed. PAM function pam_end failed");
      }
      pampst->pamh=NULL;
      pampst->result=result;
      writelog("PAM error");
      _exit(EXIT_FAILURE);
    }
  }
  //drop uid priv
  if (!set_uid_gid(user.name,user.uid,user.gid)) {//fix user
    writelog("Failed dropping owner privileges for session start");
    _exit(EXIT_FAILURE);
  }
#else
  if (!set_uid_gid(user.name,user.uid,user.gid)) {//fix user
    writelog("Failed dropping privileges for session start");
    _exit(EXIT_FAILURE);
  }
#endif
  //set umask ~047
  umask(S_IWGRP | S_IROTH | S_IWOTH | S_IXOTH);

  {//setup env
   //set DISPLAY=":0" en env del user
    if (setenv("DISPLAY",":0",0)!=0){//no overwrite
      //fprintf(stderr,"Failed to set DISPLAY envvar (%d)\n",errno);
      ewritelog("Failed to set DISPLAY envvar");
      _exit(EXIT_FAILURE);
    }
    if (setenv("USER",user.name,0)!=0){
      //fprintf(stderr,"Failed to set XTERM_SHELL envvar (%d)\n",errno);
      ewritelog("Failed to set USER envvar");
      _exit(EXIT_FAILURE);
    }
    if (setenv("SHELL",user.shell,1)!=0){
      //fprintf(stderr,"Failed to set SHELL envvar (%d)\n",errno);
      ewritelog("Failed to set SHELL envvar");
      _exit(EXIT_FAILURE);
    }
    if (setenv("XTERM_SHELL",user.shell,1)!=0){
      //fprintf(stderr,"Failed to set XTERM_SHELL envvar (%d)\n",errno);
      ewritelog("Failed to set XTERM_SHELL envvar");
      _exit(EXIT_FAILURE);
    }
    if (setenv("PATH",DEFAULT_PATH,1)!=0){//safe path default
      //fprintf(stderr,"Failed to set XTERM_SHELL envvar (%d)\n",errno);
      ewritelog("Failed to set PATH envvar");
      _exit(EXIT_FAILURE);
    }
    if (!set_envvar("XAUTHORITY","%s/.Xauthority",user.home)) {//see setup_xauth for changing path of XAUTHORITY
      writelog("Failed to set XAUTHORITY envvar");
      _exit(EXIT_FAILURE);
    }
    //-------------especifico xdg--------------------------begin

    if (!set_envvar("XDG_CONFIG_HOME","%s/.config",user.home)){
      writelog("Failed to set XDG_CONFIG_HOME envvar");
      _exit(EXIT_FAILURE);
    }
    if (!set_envvar("XDG_DATA_HOME","%s/.local/share",user.home)){
      writelog("Failed to set XDG_DATA_HOME envvar");
      _exit(EXIT_FAILURE);
    }
    /*
#ifndef USE_PAM
    {
      char envvar[MAX_PATH];
      if (!vsnprintf_managed(envvar,MAX_PATH,"/run/user/%d",user.uid)) {
	writelog("Failed to build str for envvar XDG_RUNTIME_DIR");
	_exit(EXIT_FAILURE);
      }
      if (setenv("XDG_RUNTIME_DIR",envvar,0)!=0){
	ewritelog("Failed to set XDG_RUNTIME_DIR envvar");
	_exit(EXIT_FAILURE);
      }
    }
#endif
    */
    //-------------especifico xdg--------------------------end

    if (setenv("HOME",user.home,1)!=0){
      //fprintf(stderr,"Failed to set HOME envvar (%d)\n",errno);
      ewritelog("Failed to set HOME envvar");
      _exit(EXIT_FAILURE);
      //  }
      //char* home=getenv("HOME");
      //if (home==NULL){
      ////fprintf(stderr,"Failed to get HOME envvar\n");
      //writelog("Failed to get HOME envvar");
    } else {
      if (chdir(user.home)!=0){
	//fprintf(stderr,"Failed to chdir to HOME (%d)\n",errno);
	ewritelog("Failed to chdir to HOME");
	if (errno==ENOENT) {//strange homedir dont exists, fail now
	  _exit(EXIT_FAILURE);
	}
      }
    }
  }

  {//import env vars
#ifdef USE_PAM
    //load environment from system files with pam module
    if (!load_pam_env(pampst)) {
      writelog("Failed loading environment");
      _exit(EXIT_FAILURE);
    }
#else
    //load environment from system files
    if (!load_env()) {
      writelog("Failed loading environment");
      _exit(EXIT_FAILURE);
    }
#endif
  }
  char **session=NULL;
  char sessionbin[MAX_PATH];//full path, maybe, to script or bin read from xloginrc/sessionrc
  memset(sessionbin,0,MAX_PATH);
  //const bool hasShell=has_shell(); //test if we have access to sh
  const bool hasShell=true; //we wish use wordexp; with no shell fails if subshell is called ($ or ``) but works with ""
  bool need_logout=false;
  char logout_sessionrc[MAX_PATH];
  memset(logout_sessionrc,0,MAX_PATH);
  {//get session value
    char xloginrc[MAX_PATH]; //path to xloginrc
    memset(xloginrc,0,MAX_PATH);
    //test $HOME/.xloginrc and XLOGINDIR/xloginrc
    if (!exists_xloginrc(xloginrc)) {
      //or use openbox fallback, if no value from previous
      //default value
      //session=(char*[2]){DEFAULT_SESSION,NULL};
      //session=defsession;
      session=(char**) malloc((2*sizeof(char*)));
      memset(session,0,2*sizeof(char*));
      session[0]=DEFAULT_SESSION;
    } else {//doesnt has default value because some rc exists
      if (!got_valid_line(hasShell, xloginrc, valid_not_commented_or_null_line, action_first_line, sessionbin)) {
	//writelog("Cound not get valid line in xloginrc");
	//use default
	if (!snprintf_managed(sessionbin,MAX_PATH, "%s", DEFAULT_SESSION)) {//allow ":lxde"? BUG: see if keep this
	  writelog("Path to default session file too long or other error");
	  _exit(EXIT_FAILURE);
	}
	vwritelog("Default configured session launched (%s). Please configure %s with one or more valid lines", DEFAULT_SESSION, xloginrc);
      }
      //vwritelog("Session is %s",sessionbin);
      //intprint(sessionbin,strlen(sessionbin));
      //remove unprintables '\f' '\n'
      //replace_unprintables(sessionbin);//si el bin lleva params, no sirve asignar a session[0]
      //writelog("MARK");
      /*
	char str1[]="xterm -rv";
	writelog(strtok(str1," \f\n"));
	writelog(strtok(NULL," \f\n"));
	writelog(strtok(NULL," \f\n"));
	_exit(EXIT_FAILURE);
      */
      //writelog((char*) splitcount(sessionbin," \f\n")); //provocar segfault
      if (sessionbin[0]!=':') {//use value especified directly
	if (!splitstr(" \n\r", sessionbin, &session)) {//format session array for exec
	  writelog("splitstr failed");
	  _exit(EXIT_FAILURE);
	}
	//session[0]=sessionbin;
	//writelog("MARK");
	//writelog(sessionbin);
      } else { //look for new session file
	//with new session file we have to fork command except last one, for exec
	//get session name == filename
	char *const sessionName=&sessionbin[1]; //trim ":"
	char sessionrc[MAX_PATH];
	memset(sessionrc,0,MAX_PATH);
	const char xloginpath[]=XLOGINDIR "/%s";//template
	if (!snprintf_managed(sessionrc,MAX_PATH, xloginpath, sessionName)) {
	  writelog("Path to session file too long or other error");
	  _exit(EXIT_FAILURE);
	}
	{//logout script name if exists
	  const char *const permMsg="Permissions of logout sessionrc files must be owned for root:root and 'other' readable only";
	  const char *const perm="---rw-r--r--";
	  if (build_and_test_path(XLOGINDIR "/%s_o", sessionName, permMsg, 'r', perm, logout_sessionrc)) {//no recheck parents!
	    need_logout=true;
	  }
	}
	/*
	//done early
	//open /dev/null and redirect it stderr+stdout
	if (strncmp("lxde",sessionName,4)==0) { //match first chars of "lxde"
	const int filefd=open(DEV_NULL,O_WRONLY | O_NOCTTY);
	//para usar $HOME/.lxde-errors
	if ( filefd == -1) { // | O_PATH
	const char msg[]="Open " DEV_NULL " failed";
	ewritelog(msg);
	_exit(EXIT_FAILURE);
	}
	if (dup2(filefd,STDOUT_FILENO)==-1){//redirect stdout to filefd
	ewritelog("Failed to close stdout and redirect to file");
	_exit(EXIT_FAILURE);
	}
	if (dup2(filefd,STDERR_FILENO)==-1){//redirect stderr to filefd
	ewritelog("Failed to close stderr and redirect to file");
	_exit(EXIT_FAILURE);
	}
	//writelog("lxde session detected and ready");
	}
	*/
	//open file and take data
	if (!got_valid_line(hasShell, sessionrc, valid_not_commented_or_null_line, action_login_line, sessionbin)) {
	  writelog("Cound not get valid line in sessionrc");
	  _exit(EXIT_FAILURE);
	}
	if (!splitstr(" \n\r", &sessionbin[1], &session)) {//format session array for exec (dont send const sessionbin array)
	  writelog("splitstr failed");
	  _exit(EXIT_FAILURE);
	}
	//writelog(&sessionbin[1]);
      }
    }
  }
  //session[0]="xterm";
  //writelog(sessionbin);
  /*
    writelog("Out value:");
    for (int i=0;session[i]!=NULL;i++) {
    writelog(session[i]);
    }
  */
  /*
    char** p=session;
    while (*p!=NULL){
    writelog(*p);
    p++;
    }
  */
  //intprint(session[0],strlen(session[0]));

  //run session (debe haberse indicado un valor por defecto y opcion a cambiar de sesion)
  //char *const session[]={"xterm",'\0'};//sleep(1)
  //char *const session[]={"/etc/X11/Sessions/Xsession",'\0'};
  //char *const session[]={"/etc/X11/Sessions/openbox",'\0'};//queda un sh, creo que deberia hacer exec el script (ok)
  //char *const session[]={"/etc/X11/Sessions/fvwm",'\0'};//queda un sh, creo que deberia hacer exec el script (ok)
  //char *const session[]={"/etc/X11/Sessions/lxde",'\0'};
  //char *const session[]={"xterm","bash",'\0'};
  //char *const session[]={"fvwm",'\0'};//no shell req
  //char *const session[]={"uxterm",'\0'};
  //char *const session[]={"openbox",NULL};//no shell req
  //char *const session[]={"openbox-session",NULL};
  //char *const session[]={"startlxde",NULL};
  //char *const session[]={"/usr/bin/startlxde",NULL};//uso con execve, da que no encuentra el fichero, si no lo indico; aunque fije el path en envp
  //char *const session[]={"/usr/bin/openbox-session",NULL};
  //char *const session[]={"/usr/bin/fvwm",'\0'};

  //openlog(NULL,LOG_ODELAY,LOG_DAEMON);
  //char error[ERR_MSG];
  //snprintf(error,ERR_MSG,"Error en start_session: %d",errno);
  //syslog(LOG_INFO,"%s",error);
  //closelog();

  /*
    FILE *fp;
    fp= popen("/tmp/xlogin.log","w");
    if (fp == NULL){
    fprintf(stderr,"Failed to open out stream\n");
    //return 1;
    }
    char error[ERR_MSG];
    snprintf(error,ERR_MSG,"Error en start_session: %d",errno);
    fputs(error,fp);
    //fprintf(stderr,"mcookie ended (%s)\n",cookie);
    pclose(fp);
  */
  //char *const  envp[]={ NULL };
  //char *const  envp[]={"HOME=/home/user","PATH=/etc/X11/Sessions:/usr/bin:/bin",'\0'};
  //char *const envp[]={"HOME=/home/user","SHELL=bin/bash",NULL};
  //char *const  envp[]={"HOME=/home/user","PATH=/etc/X11/Sessions:/usr/bin:/bin",NULL};
  //char *const  envp[]={"HOME=/home/user","PATH=/usr/bin","SHELL=/bin/bash",NULL};
  //char *const  envp[]={"HOME=/home/user","DISPLAY=:0",NULL};
  //char *const envp[]={"HOME=/home/user","DISPLAY=:0","PATH=/etc/X11/Sessions:/usr/sbin:/usr/bin:/sbin:/bin","SHLVL=1","PWD=/home/user",NULL};
  //char *const envp[]={"HOME=/home/user","DISPLAY=:0","PATH=/usr/sbin:/usr/bin:/sbin:/bin","USER=user",NULL};
  //char *const envp[]={"HOME=/home/user","DISPLAY=:0","PATH=/usr/bin:/bin","USER=user",NULL};//ok con execve
  //if (execve(session[0],session,envp)<0){//no shell req
  //if (execvp(*session,session)<0){//no shell req
  if (session==NULL) {//default value? BUG: do assert
    writelog("Error gettting session value");
    _exit(EXIT_FAILURE);
  }
  if (!need_logout) {
    if (execvp(session[0],session)<0){//no shell req
      free(session);
      session=NULL;
      ewritelog("Session exec failed");
      _exit(EXIT_FAILURE);
    }
  } else {
    //if logout script is required, fork last cmd and keep this process for running logout script
    pid_t child_pid=-1;//pid to wait for
    fork_prog_(session, &child_pid);
    free(session);
    session=NULL;
    //wait child of previous step and on completion run logout script
    if (!waitpid_with_log(child_pid)) {
      ewritelog("Failed waiting child (session) process from xlogin session manager");
      _exit(EXIT_FAILURE);
    }
    //run logout script
    if (!got_valid_line(hasShell, logout_sessionrc, valid_not_commented_or_null_line, action_logout_line, sessionbin)) {
      writelog("Cound not get valid line in logout sessionrc");
      _exit(EXIT_FAILURE);
    }
    _exit(EXIT_SUCCESS);
  }
}

/*
 * strzero - fill var with zeros for hiding values
 */
static void strzero(char *const  str) {//BUG check blanked true!
  explicit_bzero(str,strlen(str));
  //memset(str,0,strlen(str));
}

/*
 * check_parents_: helpper para la llamada (tail) recurtiva
 */
static bool check_parents_(const char *const permMsg, const char *const perm, char *const dir) {
  /*
  char *const dircp=strdup(dir);
  if ( dircp == NULL ) {
    ewritelog("Failed to strdup array for checking parents");
    return false;
  }
  */
  char *const cdir=dirname(dir);//after this, dir and cdir are equal
  //vwritelog("Now in %s",cdir);
  //vwritelog("Now in %s (from %s)",cdir,dircp);
  //if (strcmp(cdir,dircp)!=0) {//no baja mas de /
  if (strcmp(cdir,"/")!=0) {//no baja mas de /
    //free(dircp);
    const bool current_chk=check_perms(-1,-1,cdir,'d',-1,perm,0,0);
    //vwritelog("copy: %s: %s\n",cdir,current_chk==true?"true":"false");
    if (!current_chk) {
      vwritelog(permMsg,cdir);
    }
    return ( current_chk && check_parents_(permMsg, perm, cdir));
  } else {
    //free(dircp);
    return true;
  }
}

/*
 * check_parents: check parents are root:root o-w or customizable
 *   permMsg contains %s for getting substituted with current file cheched
 */
static bool check_parents(const char* permMsg, const char* perm, const char *const dir) {
  if (perm==NULL) {
    //perm="---######r-x";
    perm="---r#xr#xr-x";
  }
  if (permMsg!=NULL) {
    permMsg="Insecure parent: %s. Minimal requirements are root:root and o-w";//%s gets replaced with current checked dir
  }
  char *const dircopy=strdup(dir);
  if (dircopy==NULL){
    ewritelog("Error duplicating string");
    return false;
  }
  //char *cdir=dirname(dircopy);
  const bool result=check_parents_(permMsg, perm, dircopy);
  free(dircopy);
  return result;
}

/*
 *  perm_str_to_octal: convert "rwx" / "r-x" / "r##" to octal. ('#','-' means have no that perm)
 */
static short perm_str_to_octal(const char* perm) {//7-octal son los permisos denegados
  short octal=0;//'#' means don't care, we will think perm is by default allowed
  if ( (*perm=='r')  || (*perm=='#') ) {
    octal+=4;perm++;
  }
  if (*perm=='-') {
    perm++;
  }
  if ( (*perm=='w') || (*perm=='#') ) {
    octal+=2;perm++;
  }
  if (*perm=='-') {
    perm++;
  }
  if ( (*perm=='x') || (*perm=='#') ) {
    octal+=1;
  }
  if (*perm=='-') {
    perm++;
  }
  return octal;
}

/*
static short perm_str_to_octal(const char* perm) {//7-octal son los permisos denegados
  short octal=0;
  if (*perm=='r') {
    octal+=4;perm++;
  }
  if ( (*perm=='-') || (*perm=='#') ) {
    perm++;
  }
  if (*perm=='w') {
    octal+=2;perm++;
  }
  if ( (*perm=='-') || (*perm=='#') ) {
    perm++;
  }
  if (*perm=='x') {
    octal+=1;
  }
  if ( (*perm=='-') || (*perm=='#') ) {
    perm++;
  }
  return octal;
}
 */

/*
static short perm_str_ext_to_octal(const char* perm) {//7-octal son los permisos denegados
  short octal=0;
  if (*perm=='s') {
    octal+=4;perm++;
  }
  if (*perm=='-') {
    perm++;
  }
  if (*perm=='S') {
    octal+=2;perm++;
  }
  if (*perm=='-') {
    perm++;
  }
  if (*perm=='t') {
    octal+=1;
  }
  if (*perm=='-') {
    perm++;
  }
  return octal;
}
*/

/*
 *  perm_octal_to_str: convert octal value to 3chars perm="rwx" or "rx"
 */
static void perm_octal_to_str(const short octal,char perm[PERMSZ]) {// (7-octal) son los permisos denegados
  short cperm=octal;
  unsigned short i=0;
  if (octal==0){
    perm[i]='\0';
  } else {
    if ( cperm-4 >=0 ) {//have read
      cperm=cperm-4;
      perm[i++]='r';
    }
    if ( cperm-2 >=0 ) {//have write
      cperm=cperm-2;
      perm[i++]='w';
    }
    if ( cperm-1 >=0 ) {//have exec
      cperm=cperm-1;
      perm[i++]='x';
    }
    perm[i]='\0';
  }
}

/*
 *  perm_octal_to_str: convert octal value to 3chars perm="rwx" or "r-x", perm must be initalized to "---"
 */
static void perm_octal_to_str_ext(const short octal,char perm[PERMSZ]) {//care, dont do same as perm_octal_to_str
  short cperm=octal;
  unsigned short i=0;
  if ( cperm-4 >=0 ) {//have read
    cperm=cperm-4;
    perm[i]='r';
  }
  i++;
  if ( cperm-2 >=0 ) {//have write
    cperm=cperm-2;
    perm[i]='w';
  }
  i++;
  if ( cperm-1 >=0 ) {//have exec
    cperm=cperm-1;
    perm[i]='x';
  }
  i++;
  perm[i]='\0';
}

/*
 * argv2str_: helper for argv2str
 */
//static bool argv2str_(const char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod) {//BUG quitardo const!!
static bool argv2str_(char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod) {
  //single element (sz==2)
  if (argvsz==2) {//last is NULL
    if(!snprintf_managed(strchmod,szstrchmod,"%s",argv[0])) {
      writelog("argv2str error while calling snprintf_managed with argvsz==1");
      return false;
    }
    return true;
  }
  //several elements ( >1) (sz>2)
  //copy first one
  if(!vsnprintf_managed(strchmod,szstrchmod,"%s%s",argv[0],separator)) {
    writelog("argv2str error while calling snprintf_managed with argvsz>1");
    return false;
  }
  //const size_t argvszi=strlen(argv[0]);
  const size_t argvszi=strlen(strchmod);//strlen(argv[0])+strlen(separator)
  char *const strchmod_ptr=strchmod+argvszi;//taking into account NULL (must be overwrited in next call)
  return argv2str_(argv+1, argvsz-1, separator, strchmod_ptr, szstrchmod-argvszi);
}

/*
 * argv2str: converse of splitstr. Convert argv format to str joining with separator
 */
//static bool argv2str(const char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod) {//BUG quitardo const!!
static bool argv2str(char* *const argv, const size_t argvsz, const char separator[], char strchmod[], size_t szstrchmod) {
  //checks
  if (argvsz<1) {//must never happen
    vwritelog("Error calling argv2str with argvsize=%d < 1",argvsz);
    return false;
  }
  if (argvsz==1) {//NULL only
    if (szstrchmod<1) {//have room for char?
      writelog("Error calling argv2str, argvsz == 1 but szstrchmod <1");
      return false;
    }
    strchmod[0]='\0';
    return true;
  }
  //argvsz>=2
  //vwritelog("Request szargv: %d",argvsz);
  return argv2str_(argv, argvsz, separator, strchmod, szstrchmod);
}

/*
 *  perm_str_to_chmod_cmd: build chmod options accordingly to char* as "---rw-r--r--"
 */
static bool perm_str_to_chmod_cmd(const char* ptr, char strchmod[CHMODSZ]) {//supongo que fijo los tres
  char owner[PERMSZ],group[PERMSZ],other[PERMSZ],ext[PERMSZ]="---";
  char fowner[PERMSZ+3],fgroup[PERMSZ+3],fother[PERMSZ+3];//full field
  //get ext perms and forward pointer+3
  perm_octal_to_str_ext(7-perm_str_to_octal(ptr),ext);ptr+=3;//extended perm (suid,gid,sticky) as rwx / r-x
  perm_octal_to_str(7-perm_str_to_octal(ptr),owner);ptr+=3;//owner as "rwx" / "rx" / ...
  perm_octal_to_str(7-perm_str_to_octal(ptr),group);ptr+=3;//group
  perm_octal_to_str(7-perm_str_to_octal(ptr),other);//other
  //test fields
  int field1=(strlen(owner)>0 || ext[0]!='-');
  int field2=(strlen(group)>0 || ext[1]!='-');
  int field3=(strlen(other)>0 || ext[2]!='-');
  //vwritelog("with ext[]=%s",ext);
  //calculate fields number
  unsigned short i=0;
  if (field1) {
    if (!vsnprintf_managed(fowner,sizeof(fowner),"u-%s%s",(ext[0]=='r')?"s":"",owner)) { return false; }
    i++;
    //vwritelog("has field%d",i);
  }
  if (field2) {
    if (!vsnprintf_managed(fgroup,sizeof(fgroup),"g-%s%s",(ext[1]=='w')?"s":"",group)) { return false; }
    i++;
    //vwritelog("has field%d",i);
  }
  if (field3) {
    if (!vsnprintf_managed(fother,sizeof(fother),"o-%s%s",(ext[2]=='x')?"t":"",other)) { return false; }
    i++;
    //vwritelog("has field%d",i);
    //vwritelog("values: fother==%s",fother);
  }
  //fill array
  const size_t perm_argv_array_sz=i+1;//+1 for NULL
  char* perm_argv_array[perm_argv_array_sz];//variable array, don't use out of thi function
  i=0;
  if (field1) {
    perm_argv_array[i]=fowner;
    i++;
  }
  if (field2) {
    perm_argv_array[i]=fgroup;
    i++;
  }
  if (field3) {
    perm_argv_array[i]=fother;
    i++;
  }
  perm_argv_array[i]='\0';
  //printArgv(perm_argv_array);
  //join array
  if (!argv2str(perm_argv_array, perm_argv_array_sz, ",", strchmod, CHMODSZ)) {// "u-srwx,g-srwx,o-srwx" 6*3=18+2=20+1=21
    writelog("Error in argv2str");
    return false;
  }
  /*
  if (!vsnprintf_managed(strchmod,CHMODSZ,"%s%s%s%s%s%s%s%s%s%s%s",//11
		field1?"u-":"",(ext[0]=='r')?"s":"",owner,
		field1?",":"",
		field2?"g-":"",(ext[1]=='w')?"s":"",group,
		field2?",":"",
		field3?"o-":"",(ext[2]=='x')?"t":"",other) ) {//11+12+1=24? "u-srwx,g-srwx,o-srwx" 6*3=18+2=20+1=21
    return false;
  }
  */
  return true;
}

/*
static void perm_str_to_chmod_cmd(const char* ptr, char strchmod[CHMODSZ]) {//supongo que fijo los tres
  //BUG: necesita concatenar con separador para simplificar
  char owner[PERMSZ],group[PERMSZ],other[PERMSZ],ext[PERMSZ]="---";
  //get ext perms and forward pointer+3
  perm_octal_to_str_ext(7-perm_str_to_octal(ptr),ext);ptr+=3;//extended perm (suid,gid,sticky) as rwx / r-x
  perm_octal_to_str(7-perm_str_to_octal(ptr),owner);ptr+=3;//owner as "rwx" / "rx"
  perm_octal_to_str(7-perm_str_to_octal(ptr),group);ptr+=3;//group
  perm_octal_to_str(7-perm_str_to_octal(ptr),other);//other
  int field1=(strlen(owner)>0 || ext[0]!='-');
  int field2=(strlen(group)>0 || ext[1]!='-');
  int field3=(strlen(other)>0 || ext[2]!='-');
  //if (!snprintf(strperm,sizeof(strperm),"chmod %s%s%s",)) {
  if (!vsnprintf_managed(strchmod,CHMODSZ,"%s%s%s%s%s%s%s%s%s%s%s",//11
		field1?"u-":"",(ext[0]=='r')?"s":"",owner,
		field1?",":"",
		field2?"g-":"",(ext[1]=='w')?"s":"",group,
		field2?",":"",
		field3?"o-":"",(ext[2]=='x')?"t":"",other) ) {//11+12+1=24? "u-srwx,g-srwx,o-srwx" 6*3=18+2=20+1=21
    exit(EXIT_FAILURE);//BUG corregir para no mezclar salida a child o parent
  }
}

 */
/*
static void perm_str_to_chmod_cmd(const char* ptr,char strchmod[24]) {//supongo que fijo los tres
  char owner[4],group[4],other[4];
  //get ext perms and forward pointer+3
  ptr+=3;//skip extendidos perm (suid,gid,sticky)
  perm_octal_to_str(7-perm_str_to_octal(ptr),owner);ptr+=3;//owner
  perm_octal_to_str(7-perm_str_to_octal(ptr),group);ptr+=3;//group
  perm_octal_to_str(7-perm_str_to_octal(ptr),other);//other
  //if (!snprintf(strperm,sizeof(strperm),"chmod %s%s%s",)) {
  if (!snprintf(strchmod,24,"u-s%s,g-s%s,o-t%s",owner,group,other)) {//11+12+1=24
    exit(EXIT_FAILURE);//BUG corregir para no mezclar salida a child o parent
  }
}
 */

/*
static void perm_str_to_chmod_cmd(const char* ptr,char strperm[21]) {//supongo que fijo los tres
  unsigned short offset=3;
  char* strptr=strperm;
  char extperm[4];//suid/gid/sticky perms
  //get ext perms and forward pointer+3
  perm_octal_to_str_ext(perm_str_to_octal(ptr),extperm);ptr+=3;
  //owner part
  *strptr='u';++strptr;*strptr='=';++strptr;//"u="
  perm_octal_to_str(perm_str_to_octal(ptr),strptr);ptr+=3;
  if (*strptr=='\0') {
  if (extperm[0]=='s') { offset+=2; };
  if (extperm[0]=='s') { offset+=2; };strptr+=offset;offset=3;
  perm_octal_to_str(perm_str_to_octal(ptr),strptr);ptr+=3;strptr+=3;//owner
  perm_octal_to_str(perm_str_to_octal(ptr),strptr);ptr+=3;strptr+=3;//group
  perm_octal_to_str(perm_str_to_octal(ptr),strptr);//other
}
*/

/*
 * test_perms_: runner to test_perms
 */
static bool test_perms_(const mode_t* perms, const mode_t perm,const char* strperm) {
  //terminal case
  if (*strperm=='\0')
    return true;
  //      must not have this permission      ,            must have this permission
  if ( ((*strperm=='-') && (*perms & perm)) || ((*strperm!='-') && (*strperm!='#') && !(*perms & perm)) ) {
    return false;//cuts early
  }
  return test_perms_(++perms,perm,++strperm);//check next case
}

/*
static bool test_perms_(const mode_t* perms, const mode_t perm,const char* strperm) {
  //terminal case
  if (*strperm=='\0')
    return true;

  if (*strperm=='#') {//don't make test, check next
    return test_perms_(++perms,perm,++strperm);
  } else if (*strperm=='-') {//make test and check next
    return ( ((*perms & perm)?false:true) && test_perms_(++perms,perm,++strperm) );//must not have this permission
  } else {//make test and check next
    return ( ((*perms & perm)?true:false) && test_perms_(++perms,perm,++strperm) );//must have this perm
  }
}
*/

/*
 * test_perms: check strperm (char array perms) with perm
 *   format for strperm is "-w-rw-rw-r--" ; '#' means don't care, '-' means negated that perm (position based), for especial "rwxrwxrwxrwx" any char works too
 *   for the first 3 one means extended perms (suid,gid,sticky)
 */
static bool test_perms(const mode_t perm,const char strperm[FPERMSZ]) {
  const mode_t perms[]={S_ISUID,S_ISGID,S_ISVTX,S_IRUSR,S_IWUSR,S_IXUSR,S_IRGRP,S_IWGRP,S_IXGRP,S_IROTH,S_IWOTH,S_IXOTH};//12
  return test_perms_(perms,perm,strperm);
}

/*
 *  test_filetype: check if file match filetype
 */
static bool test_filetype(const mode_t modetype, const char type) {
  if (type=='d') {
    if(!S_ISDIR(modetype)) {
      writelog("Error: filetype is not directory");
      return false;
    }
  } else if (type=='r') {
    if (!S_ISREG(modetype)) {
      writelog("Error: filetype is not regular file");
      return false;
    }
  } else if (type=='s') {
    if (!S_ISSOCK(modetype)) {
      writelog("Error: filetype is not socket");
      return false;
    }
  } else if (type=='c') {
    if (!S_ISCHR(modetype)) {
      writelog("Error: filetype is not character device");
      return false;
    }
  } else if (type=='b') {
    if (!S_ISBLK(modetype)) {
      writelog("Error: filetype is not block device");
      return false;
    }
  } else if (type=='f' ) {
    if (!S_ISFIFO(modetype)) {
      writelog("Error: filetype is not fifo");
      return false;
    }
  } else if (type=='l') {
    if (!S_ISLNK(modetype)) {
      writelog("Error: filetype is not link");
      return false;
    }
  } else {
    writelog("Error: filetype not recognized");
    return false;
  }
  return true;
}

/*
 * check_perms: check if file have perms specified
 *   file is filepath, strperms es "---rw-rw-r--" see test_perms
 *   dirFd, fileFd are active if >=0 in that order
 *   type: filetype check active if != ' ' see test_filetype
 *   nlinks: hardlinks check active if >0
 *   uid,gid checks active if >0
 *   man 7 inode, man fstat, man fstatat, man strmode
 */
static bool check_perms(const int dirFd, const int fileFd, const char* filepath, const char type, const short nlinks, const char strperm[FPERMSZ],
			const short uid, const short gid) {
  const unsigned short sz=(unsigned short) strlen(strperm);
  if ( strlen(strperm) != FPERMSZ-1 ) {//check proper request
    fprintf(stderr,"Invalid permissions, needed 12 chars, current %d for file %s\n",sz,filepath);
    vwritelog("Invalid permissions, needed 12 chars, current %d for file %s\n",sz,filepath);
    return false;
  }
  struct stat buf;
  if (dirFd>=0) {//use dirFd if supplied
    if (fstatat(dirFd,filepath,&buf,AT_SYMLINK_NOFOLLOW)<0) {//good in sticky dirs or files we cant get a fd
      fprintf(stderr,"Could not read file %s: %m\n",filepath);
      vwritelog("Could not read file %s: %m",filepath);
      return false;
    }
  } else if (fileFd>=0) {//use fileFd if supplied
    if (fstat(fileFd,&buf)<0) {
      fprintf(stderr,"Could not read file %s: %m\n",filepath);
      vwritelog("Could not read file %s: %m",filepath);
      return false;
    }
  } else {
    if (stat(filepath,&buf)<0) {
      fprintf(stderr,"Could not read file %s: %m\n",filepath);
      vwritelog("Could not read file %s: %m",filepath);
      return false;
    }
  }
  //test file type
  if ( (type!=' ') && (!test_filetype(buf.st_mode,type)) )  {
    return false;
  }
  //test number of hardlinks
  if ( (nlinks > 0) && (buf.st_nlink > (nlink_t) nlinks) ) {//for directories, is a count of direct subfolders
    return false;
  }
  //vwritelog("Octal perms # %jo #",(uintmax_t) buf.st_mode);//da 100664 no exactamente octal
  //vwritelog("Octal perms # %10.10s #",sperm(buf.st_mode));//da ? no exactamente octal
  //vwritelog("Octal perms # %o #",(buf.st_mode & 0000777));//da 664 octal
  //char test[FPERMSZ]="---rwxr-x---";//750
  //char test[FPERMSZ]="---r--r--r--";//444
  //char test[FPERMSZ]="---r##r##r--";//>=4>=44
  //vwritelog("file %s, perm %o, test %s, result %s ",filepath,(buf.st_mode & 0000777),test,(test_perms(buf.st_mode,test)?"true":"false"));
  //vwritelog("test grp write %s",(buf.st_mode & S_IWGRP)?"true":"false");//ok
  //if ((buf.st_mode & 0000007) != operms ) {//have more octal perm than allowed
  if (!test_perms(buf.st_mode,strperm)) {
    //calculate negated perms
    char strchmod[CHMODSZ];
    memset(strchmod,0,CHMODSZ);
    if (!perm_str_to_chmod_cmd(strperm,strchmod)){
      writelog("Error in perm_str_to_chmod_cmd");
      return false;
    }
    fprintf(stderr,"Insecure file %s. Try running 'chmod %s %s'\n",filepath,strchmod,filepath);
    vwritelog("Insecure file %s. Try running 'chmod %s %s'",filepath,strchmod,filepath);
    /*
    char chmodperm[4]="   ";
    perm_octal_to_str((7-operms),chmodperm);
    //fprintf(stderr,"mode: %d\n",buf.st_mode & 0000007); //select less significant bit (other)
    fprintf(stderr,"Insecure file %s. Try running 'chmod o-%s %s'\n",filepath,chmodperm,filepath);
    vwritelog("Insecure file %s. Try running 'chmod o-%s %s'\n",filepath,chmodperm,filepath);
    */
    return false;
  }
  if ((uid >= 0) && ( buf.st_uid!= (uid_t) uid )) {
    fprintf(stderr,"Insecure owner for file %s (%d). Try running 'chown %d %s'\n",filepath,buf.st_uid,uid,filepath);
    vwritelog("Insecure owner for file %s (%d). Try running 'chown %d %s'",filepath,buf.st_uid,uid,filepath);
    return false;
  }
  if ((gid >= 0) && ( buf.st_gid!= (gid_t) gid )) {
    fprintf(stderr,"Insecure group for file %s (%d). Try running 'chgrp %d %s'\n",filepath,buf.st_gid,gid,filepath);
    vwritelog("Insecure group for file %s (%d). Try running 'chgrp %d %s'",filepath,buf.st_gid,gid,filepath);
    return false;
  }
  return true;
}

#ifdef USE_PAM
/*
 * show_pam_error: tranlate errnum to str
 */
static void show_pam_error(pam_handle_t *const pamh, const int errnum) {
  bool warn=false;
  if (pam_misc_conv_died==1) { warn=true; }//check if timeout reached
  if (!warn) {
    fprintf(stderr,"%s",pam_strerror(pamh,errnum));
    writelog(pam_strerror(pamh,errnum));
  }//translate error msg
}

/*
 * set_pam_timeout: reach timeout on login prompt waiting for password
 */
static bool set_pam_timeout(void) {
  //calculate timeout for pam
  const time_t ctime=time(NULL);
  if (ctime == ((time_t) -1)) {
    ewritelog("Error, time() function failed. Problem setting pam timeout");
    return false;
  }
  //set timeout for pam
  pam_misc_conv_die_time=ctime + ((time_t) LOGIN_TIMEOUT);
  //int pam_misc_conv_died; //==1 if timeout occurs (checked in show_pam_error)
  return true;
}
#endif

/*
 * set_utmp: write utmp/wtmp entries
 */
static bool set_utmp(char name[FIELDSZ], pid_t child_sid, const char* ttyNumber) {//rodar root:utmp y check rw-rw-r--
  const char* utmp_path=_PATH_UTMP;
  const char* wtmp_path=_PATH_WTMP;
  const char* utmp_group_name=UTMP_GROUP_NAME;
  const bool hasUtmp=access(utmp_path,R_OK)==0? true:false;
  const bool hasWtmp=access(wtmp_path,R_OK)==0? true:false;

  if (!hasUtmp && !hasWtmp){
    return true;
  }

  //vwritelog("Trying to find utmp group name: %s",utmpgroup);
  //get utmp group
  errno=0; //req by getgrname
  const struct group* utmpgrpst=getgrnam(utmp_group_name);
  if (utmpgrpst==NULL) {
    if (errno!=0) {
      vwritelog("Failed to get gid of '%s' group: %m",utmp_group_name);
    } else {
      vwritelog("Utmp group name '%s' not found",utmp_group_name);
    }
    return false;
  }
  const gid_t utmpgroup=utmpgrpst->gr_gid;
  //vwritelog("Found utmp group gid: %d",utmpgroup);
  utmpgrpst=NULL;

  //const gid_t utmpgroup=UTMP_GROUP;
  //previous perms checks
  if ( ( hasUtmp && ( !check_perms(-1,-1,utmp_path, 'r', 1, "---rw-rw-r--",0,utmpgroup) || !check_parents(NULL,NULL,utmp_path) ) ) ||
       ( hasWtmp && ( !check_perms(-1,-1,wtmp_path, 'r', 1, "---rw-rw-r--",0,utmpgroup) || !check_parents(NULL,NULL,wtmp_path) ) ) ) {
    fprintf(stderr,"utmp/wtmp file integrity must be keep (see: man 5 utmp)\n");
    sleep(10);
    return false;
  }

  struct utmp ut;
  struct timeval tv;

  //initialization
  memset(&ut,0,sizeof(ut));

  gettimeofday(&tv, NULL);
  ut.ut_tv.tv_sec = tv.tv_sec;
  ut.ut_tv.tv_usec = tv.tv_usec;

  //snprintf_managed(user.home,sizeof(user.home),"%s","/")){
  const short namesz=UT_NAMESIZE;
  const short utidsz=4; //see /usr/include/bits/utmp.h

  if ( !snprintf_managed(ut.ut_user,namesz,"%s",name) ||
      !snprintf_managed(ut.ut_id,utidsz,"c%s",ttyNumber) ) {
    return false;
  }
  ut.ut_session=child_sid;

  //login(ut_ptr);
  login(&ut);
  //writelog("Finished utmp record");
  return true;
}

/*
 * authenticate user: return values < 0 means error
 */
static int auth_user(struct pamdata *const pampst) {
  struct passwd *sp=NULL;//passwd struct with user data (.pw_name, .pw_passwd, .pw_uid, .pw_gid, .pw_shell, .pw_dir:home)
  struct group *sg=NULL; //group struct with group data (.gr_name, .gr_gid)
#ifndef USE_PAM
(void) pampst;
  struct spwd *ss=NULL; //shadow struct with user data (.sp_pwdp:pass,sp_namp:name)
  bool use_shadow_pass=false; //if passwd having crypth pass field
#endif
  int pw_diff=1; //result comparing cipher passwords

  if (strcmp(user.name, ROOTUSER)==0) {
    fprintf(stderr,"Don't login root user with xlogin\n");
    sleep(2);
    return 1;
  }
  /*
  //keep default action: kill process
  if (signal(SIGALRM,sigIgnore)==SIG_ERR){
    writelog("Failed to setup xlogin timeout catcher");
    exit(EXIT_FAILURE);
  }
  */
  {//check if user exists
    //get user data from passwd file
    //BUG: NO USAR ROOT PARA LA TAREA!!
    sp=getpwnam(user.name);//BUG: duplicate struct with memcp?
    if (sp==NULL){//invalid user
      alarm(LOGIN_TIMEOUT);//kill process if timeout reaches (default action)
      char* clear = getpass2 ("Password: ");
      strzero(clear);
      free(clear);
      clear=NULL;
      alarm(0);
      sleep(2);
      fprintf(stderr,"Incorrect password for %s.\n", user.name);
      sleep(2);
      return 2;
    }
    user.uid=sp->pw_uid;
    user.gid=sp->pw_gid;
    if (
	!snprintf_managed(user.shell,sizeof(user.shell),"%s",sp->pw_shell)//global
	||
	!snprintf_managed(user.home,sizeof(user.home),"%s",sp->pw_dir)//global
	){
      sp=NULL;
      return -1;
    }
    //check has 'x' in passwd field
    if (sp->pw_passwd[0]=='x') {//field hasn't password, have to see shadow pass
      sp=NULL;
#ifndef USE_PAM
      use_shadow_pass=true;
#endif
    } else if ((sp->pw_passwd[0]=='*') || (sp->pw_passwd[0]=='!')) {//account locked
      sp=NULL;
      return 3;
    } else if (sp->pw_passwd[0]=='\0') {//account without password, fail always
      sp=NULL;
      fprintf(stderr,"Account %s without password. Access denied\n",user.name);
      sleep(5);
      return 4;
    }

    if (user.shell==NULL){//give default
      if (!snprintf_managed(user.shell,sizeof(user.shell),"%s","/bin/sh")){
	return -1;
      }
    }
    if (user.home==NULL){//give default
      if (!snprintf_managed(user.home,sizeof(user.home),"%s","/")){
        return -1;
      }
    }
    //denegate root
    if (user.uid==0 || user.gid==0){
      fprintf(stderr,"Don't login root rights user with xlogin\n");
      sleep(2);
      return 1;
      /*
      alarm(LOGIN_TIMEOUT);
      getpass2 ("Password: ");
      alarm(0);
      sleep(1);
      return false;
      */
    }
    //denegate if user.home is o+rwx
    if (!check_perms(-1,-1,user.home,'d',-1,"---rwx###---",user.uid,user.gid)) {
      //fprintf(stderr,"Insecure user homedir, magic cookie could be accesible to others. Try running 'chmod o-rwx %s'\n",user.home);
      fprintf(stderr,"Insecure user homedir, magic cookie could be accesible to others. Try fixing permissions of %s\n",user.home);
      sleep(10);
      return -2;
    }
    //check parents
    if (!check_parents(NULL,NULL,user.home)) {
      fprintf(stderr,"Insecure parents of homedir, magic cookie could be accesible to others. Try fixing permissions of parents\n");
      sleep(10);
      return -3;
    }
    //check if primary group match username (unique)
    sg=getgrgid(user.gid);
    if (sg==NULL){
      fprintf(stderr,"Invalid group\n");
      sleep(2);
      return -3;
    }
    if (!snprintf(user.group,sizeof(user.group),"%s",sg->gr_name)){
      sg=NULL;
      return -1;
    }
    sg=NULL;
    if (strcmp(user.name,user.group)!=0){
      fprintf(stderr,"Username and groupname must match. Don't share groups!\n");
      sleep(2);
      return -4;
    }
  }

#ifdef USE_PAM
  {//validate password
    /*
    struct pam_conv conv = {
      misc_conv,
      NULL
    };
    //set timeout for pam
    if (!set_pam_timeout()) {
      return false;
    }
    pam_handle_t *pamh=NULL;
    int result=pam_start("login", user.name, &conv, &pamh);
    */
    pam_handle_t* pamh=pampst->pamh;
    int result=pampst->result;

    if (result==PAM_SUCCESS) {//autentication
      result=pam_authenticate(pamh,0);
    } else {
      goto pamcleanup;
    }

    if(result==PAM_SUCCESS) {//account validation
      result=pam_acct_mgmt(pamh,0);
    } else {
      goto pamcleanup;
    }

    //user was authenticated, now setup session
    if (result==PAM_SUCCESS) {//create session
      result=pam_open_session(pamh,0);//root rights required!
    } else {
      goto pamcleanup;
    }

    /*
    //user was authenticated, now setup session
    if (result==PAM_SUCCESS) {//setting credentials
      result=pam_setcred(pamh,PAM_ESTABLISH_CRED);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_acct_mgmt
    }

    if (result==PAM_SUCCESS) {//create session
      result=pam_open_session(pamh,0);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_setcred
    }
    */

    //pampst->pamh=pamh;

    if (result==PAM_SUCCESS) {
      pw_diff=0;
      pampst->result=result;
    } else {
    pamcleanup:
      pampst->result=result;
      //show_pam_error(pamh, result, &warned);//from pam_open_session
      show_pam_error(pamh, result);//from pam_acct_mgmt
      sleep(2);
      /*
      //call pam_end on error for cleanup
      if ( (result=pam_end(pamh,result)) != PAM_SUCCESS ) {
	show_pam_error(pamh, result, &warned);
      }
      */
      return -5;
    }
    /*
    if (result==PAM_SUCCESS) {//close session
      result=pam_close_session(pamh,0);
    }

    if (result==PAM_SUCCESS) {//deletting credentials
      result=pam_setcred(pamh,PAM_DELETE_CRED);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_close_session
    }

    if (result==PAM_SUCCESS) {//cleanup
      result=pam_end(pamh,result);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_setcred
    }

    if (result!=PAM_SUCCESS) {
      show_pam_error(pamh, result, &warned);//from pam_end
      pamh=NULL;
      *bresult=result;
      writelog("PAM function pam_end failed");
      return false;
    }
    */
    /*
    if (pam_end(pamh,result)!=PAM_SUCCESS) {
      pamh=NULL;
      *bresult=result;
      writelog("Cleanup failed. PAM function pam_end failed");
      return false;
    }
    pamh=NULL;
    */
  }
#else //!USE_PAM
  {//validate password
    alarm(LOGIN_TIMEOUT);
    char* clear = getpass2("Password: ");//do no apply register
    alarm(0);//BUG write timeout msg to end function smoothly, now it gets killed
    if (NULL == clear) {
      fprintf(stderr,"Couldn't get typed password: %s",strerror(errno));
      sleep(2);
      return 5;
    }

    char* crypt_passwd=NULL;
    if (use_shadow_pass) {
      //get shadow pass
      ss=getspnam(user.name);
      if (ss==NULL){
	strzero(clear);
	free(clear);
	clear=NULL;
	fprintf(stderr,"Bad shadow file state or other error\n");
	sleep(2);
	return -6;
      }
      crypt_passwd=ss->sp_pwdp;//BUG no he usado libreria para copiar string
      ss=NULL;//BUG: es suficiente con esto o sobreescribo ss->sp_pwdp?
    } else {
      //get passwd pass
      crypt_passwd=sp->pw_passwd;
      sp=NULL;//BUG: es suficiente con esto o sobreescribo ss->sp_pwdp?
    }
    //check locked account
    if ((crypt_passwd[0]=='*') || (crypt_passwd[0]=='!')) {//account locked
      strzero(clear);
      strzero(crypt_passwd);
      free(clear);
      clear=NULL;
      crypt_passwd=NULL;
      sleep(2);
      return 3;
    }
    {//check crypt algorithm
      //read 'man crypt(3)'
      const char cryptid=CRYPT_ID;
      //we hope crypt_passwd[1] be a number (Algorithm Id) as pointed in manpage
      if ((crypt_passwd[1] < cryptid)) {
	strzero(clear);
	strzero(crypt_passwd);
	free(clear);
	clear=NULL;
	crypt_passwd=NULL;
	fprintf(stderr,"Crypt algorithm too weak");
	sleep(2);
	return -7;
      }
    }
    char* cipher = crypt(clear,crypt_passwd);
    strzero(clear);
    free(clear);
    clear=NULL;

    if (NULL==cipher) {
      strzero(crypt_passwd);
      crypt_passwd=NULL;
      fprintf (stderr,"Failed to crypt password with previous salt: %s\n",strerror (errno));
      sleep(2);
      return -8;
    }
    pw_diff=strcmp(cipher, crypt_passwd);
    strzero(crypt_passwd);
    crypt_passwd=NULL;
    strzero (cipher);
    cipher=NULL;
  }
  #endif

  if ( pw_diff==0 ) {//==0 => SUCCESS AUTH
    return 0;
  } else {
    sleep(1);
    fprintf(stderr,"Incorrect password for %s.\n", user.name);
    sleep(2);
    return 6;
  }
}

#define main_failure(label) failed=true;goto label;
#define main_success(label) goto label;

int main(int argc,char *argv[]) {
  writelog("xlogin v" PACKAGE_VERSION " starting");
  /*
  for (int i=0;i<argc;i++){
    fprintf(stdout,"argv[%d]: %s\n",i,argv[i]);
  }
  man optarg(3) optarg(3p)
  AGETTY
  0: /bin/xlogin2
  1: --
  2: username
  3: '\0'
  */

  #ifdef TESTUNIT
  //testunit
  if (!testunit()){ exit(EXIT_FAILURE); }
  #endif

  //sanitize enviroment
#ifndef USE_PAM
  if (clearenv()!=0) {
    writelog("Failed to clear environment. Maybe you have changed it in non-standard way?");
    exit(EXIT_FAILURE);
  }//systemd do 'init' work and set some env vars
#endif
  {//sane checks
    if ( argc<1 ) {
      writelog("Al least username must be provided in command line of xlogin");
      exit(EXIT_FAILURE);
    }
    if (argc>3) {
      writelog("Usage: xlogin <username> or xlogin -- <username>");
      exit(EXIT_FAILURE);
    }
    //check rootfs perms
    if (!check_perms(-1,-1,"/", 'd', -1, "---rwxr#xr-x",0,0)) {
      writelog("Invalid rootfs perms. Must be root:root owned and 'other' no writeable");
      exit(EXIT_FAILURE);
    }
    //check no normal user running xlogin
    if ( getuid() != ((uid_t) 0) ) {
      fprintf(stderr,"Run xlogin only as root\n");
      writelog("Run xlogin only as root");
      exit(EXIT_FAILURE);
    }
  }
  {//get username from getty, trimming to FIELDSZ
    const char *const getty_username=argv[argc-1];
    //this is the only on field from user struct which is filled out of auth_user
    if (!snprintf_managed(user.name,FIELDSZ,"%s",getty_username)){//global
      writelog("Failed to set username field");
      exit(EXIT_FAILURE);
    }
  }

  bool failed=false;//error track and cleanup tasks

#ifdef USE_PAM
  if (!exists_pamconfig()) {//check config file exists
    exit(EXIT_FAILURE);
  }
  struct pam_conv conv = {
    misc_conv,
    NULL
  };
  struct pamdata pamst;
  {//user authentication and pam setup
    //set timeout for pam
    if (!set_pam_timeout()) {
      exit(EXIT_FAILURE);
    }
    pam_handle_t *pamh=NULL;
    pamst.result=pam_start("xlogin", user.name, &conv, &pamh);
    pamst.pamh=pamh;

    if (pamst.result!=PAM_SUCCESS) {
      show_pam_error(pamst.pamh, pamst.result);
      writelog("PAM error: Imposible authenticate user");//some feedback
      main_failure(pam_end);
    }

    {//authenticate user
      const int bresult=auth_user(&pamst);
      if ( bresult!=0 ) {//USE_PAM
	if (bresult<0) {
	  main_failure(exit);
	} else {
	  main_success(exit);
	}
	//writelog("Authentication failure");
      }
    }
  }
#else
  {//authenticate user
    const int bresult=auth_user(NULL);
    if ( bresult!=0 ) {//!USE_PAM
      writelog("Authentication failure");
      if (bresult<0) {
	main_failure(exit);
      } else {
	main_success(exit);
      }
      //exit(EXIT_FAILURE);
    }
  }
#endif
  {//redirect stdout, stderr to /dev/null
    const int devnullFdWr=open(DEV_NULL,O_WRONLY | O_NOCTTY);
    if (devnullFdWr<0) {
      ewritelog("Error opening " DEV_NULL " writeonly");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    if (dup2(devnullFdWr,STDOUT_FILENO)<0) {
      ewritelog("Failed closing stdout");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    if (dup2(devnullFdWr,STDERR_FILENO)<0) {
      ewritelog("Failed closing stderr");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    if (close(devnullFdWr)==-1) {
      ewritelog("Failed to close redirected file desciptor");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
  }

  //get tty number
  //get tty device
  const char* ttydev=ttyname(STDIN_FILENO); //da /dev/tty7 para vt7
  if (ttydev==NULL) {
    ewritelog("Failed to get current ttydevice");
    main_failure(exit);
    //exit(EXIT_FAILURE);
  }

  //translate ttydev to vtdev (just before closing FDs)
  const char* ttyNumber=ttydev + strlen("/dev/tty"); //skip "/dev/tty"
  char default_vt[]="vt00";
  //const short default_vtsz=strlen(default_vt)+1;
  if (!snprintf_managed(default_vt,sizeof(default_vt),"vt%s",ttyNumber)) {
    writelog("Error getting default_vt string");
    main_failure(exit);
    //exit(EXIT_FAILURE);
  }

  {//check of xlogin system dir
    const char system_xlogin_dir[]=XLOGINDIR;
    if (access(system_xlogin_dir,F_OK)!=0) {
      ewritelog("Directory required, " XLOGINDIR ", missing or other error");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
  }

  {//check /proc is mounted hidepid=invisible
    if (!is_proc_secure()) {
      writelog("/proc security too weak");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
  }

  {//write utmp/wtmp login records
    //get sid current process
    const pid_t psid=getsid(0);
    if (psid<0) {
      ewritelog("Failed to get process sid");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    //write utmp login record //BUG puede rodar con menos permisos!! (root:utmp)
    if (!set_utmp(user.name,psid,ttyNumber)) {
      writelog("Error filling utmp struct");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
  }
  //importante
  //setsid();
  //esto tambien elimina el controlling terminal, visto con ps, sale ?
  //man 3p close (undefined behaviour?) BUG?? si, hacer >/dev/null los tres
  /*
  close(STDIN_FILENO);//0
  close(STDOUT_FILENO);//1
  close(STDERR_FILENO);//2
  */
  {//redirect stdin to /dev/null
    const int devnullFdRd=open(DEV_NULL,O_RDONLY | O_NOCTTY);
    if (devnullFdRd<0) {
      const char msg[]="Error opening " DEV_NULL " readonly";
      ewritelog(msg);
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    if (dup2(devnullFdRd,STDIN_FILENO)<0) {
      ewritelog("Failed closing stdin");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
    if (close(devnullFdRd)==-1) {
      ewritelog("Failed to close redirected file desciptor");
      main_failure(exit);
      //exit(EXIT_FAILURE);
    }
  }

  //start xserver
  const pid_t xserver_pid=start_xserver(default_vt);
  if ( xserver_pid < 0 ) {//non blocking start
    //fprintf(stderr,"Failed to start xserver\n");
    writelog("Failed to start xserver");
    main_failure(exit);
    //exit(EXIT_FAILURE);
  }

  //man 2 prctl
  if (prctl(PR_SET_CHILD_SUBREAPER,1)!=0) {//be xlogin child subreaper
    ewritelog("Failed setting main thread as child rubreaper");
    main_failure(cleanup);
    //exit(EXIT_FAILURE);
  }
  //start session
  const pid_t child_pid=fork();
  if ( child_pid < 0) {
    writelog("Failed to fork main process");
    main_failure(cleanup);
    //exit(EXIT_FAILURE);
  } else if (child_pid == 0) {//child
    //create a session
    if (setsid()==((pid_t) -1)) { ewritelog("Failed to create process group for child session"); };
#ifdef USE_PAM
    start_session(&pamst);
#else
    start_session(NULL);
#endif
  }
  //parent
  // bash: ps axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm
  //wait(NULL);
  //waitpid(child_pid,NULL,0);
  //vwritelog("xlogin will wait to pid: %d",child_pid);

  //dont track changes because runs before child change sid
  //const pid_t child_sid=getsid(child_pid); //getpgid,getpgrp
  //if (child_sid==-1) {
  //  vwritelog("Error getting childs process group (child_pid: %d): %m",child_pid);
  //}

  //wait immediate child
  if (!waitpid_with_log(child_pid)) {
    ewritelog("Failed waiting child (session) process");
    main_failure(cleanup);
    //exit(EXIT_FAILURE);
  }

  //vwritelog("Killing pg: %d",child_pid);

  //kill child_pid because its child_sid
  if (killpg(child_pid, SIGINT)!=0) {//non fatal
    vwritelog("Failed to kill child process group %d: %m",child_pid);
    //exit(EXIT_FAILURE);
  }

  //wait subchild process group
  //as subreaper could wait for childs adquired
  if (!waitsid_with_log(child_pid)) {//BUG need timeout for killing X
    ewritelog("Error waiting sub childs process in reaper parent");
  }

cleanup:
  //kill xserver
  if (kill(xserver_pid, SIGINT)!=0) {//BUG: reset and shutdown options??
    //fprintf(stderr,"Failed to kill xserver (%d)\n",errno);
    ewritelog("Failed to kill xserver");
    //main_failure(exit);
    exit(EXIT_FAILURE);
    //} else {
    //writelog("Xorg killed successfully");
  }

  /*
  {//kill child process group
    //no me ha servido porque al hacer getsid() sobre el child, el parent no ve el cambio al llamar a getsid(child_pid)
    //kill TPGID==-1
    //kill sid de child (SIGTERM/SIGKILL)
    //if (killpg(child_sid, SIGINT)!=0) {
    //const pid_t child_pg=getpgid(child_pid);
    //const pid_t child_sid=getsid(child_pid);
    //const pid_t child_sid=getsid(0);//for killing process group
    if (child_sid==-1) {
      vwritelog("Error getting childs process group (child_pid: %d): %m",child_pid);
    } else {
      //killpg(child_sid, SIGINT);//no matter if fails
      if (killpg(child_sid, SIGINT)!=0) {
	vwritelog("Failed to kill child process group %d: %m",child_sid);
	//exit(EXIT_FAILURE);
      }
    }
    writelog("Kill signal sent");
  }
  */

  {//wait child process group
    //as subreaper could wait for childs adquired
    //for killing process group
    //get sid of this process
    const pid_t child_sid=getsid(0); //getpgid,getpgrp
    if (child_sid==(pid_t) -1) {
      ewritelog("Error getting sid of parent subreaper");
      main_failure(exit);
    }
    if (!waitsid_with_log(child_sid)) {
      ewritelog("Error waiting childs process in reaper parent");
    }
  }

  //wait xserver ends
  if (waitpid(xserver_pid,NULL,0)!=xserver_pid) {
    ewritelog("Failed to wait xserver end");
    main_failure(exit);
  }

  exit:
#ifdef USE_PAM
  {//close pam session
    //pam_handle_t *const pamh=pamst.pamh;
    //int result=pam_close_session(pamst.pamh,0);//close session
//pam_cleanup:
    pamst.result=pam_close_session(pamst.pamh, 0);//close session
    if (pamst.result!=PAM_SUCCESS) { show_pam_error(pamst.pamh, pamst.result); }

    pamst.result=pam_setcred(pamst.pamh, PAM_DELETE_CRED);//deletting credentials
    if (pamst.result!=PAM_SUCCESS) { show_pam_error(pamst.pamh, pamst.result); }

  pam_end:
    pamst.result=pam_end(pamst.pamh, pamst.result);//cleanup
    if (pamst.result!=PAM_SUCCESS) { show_pam_error(pamst.pamh, pamst.result); }

    pamst.pamh=NULL;

    if (!failed && pamst.result!=PAM_SUCCESS) {
      failed=true;
    }


    /*
    if (result==PAM_SUCCESS) {//deletting credentials
      result=pam_setcred(pamh,PAM_DELETE_CRED);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_close_session
      pam_setcred(pamh,PAM_DELETE_CRED);
    }

    if (result==PAM_SUCCESS) {//cleanup
      result=pam_end(pamh,result);
    } else {
      show_pam_error(pamh, result, &warned);//from pam_setcred
    }

    if (result!=PAM_SUCCESS) {
      show_pam_error(pamh, result, &warned);//from pam_end
     //call pam_end on error for cleanup
     if (pam_end(pamh,result)!=PAM_SUCCESS) {
       writelog("Cleanup failed. PAM function pam_end failed");
     }
      pamst.pamh=NULL;
      writelog("PAM function pam_end failed");
      exit(EXIT_FAILURE);
    }
    pamst.pamh=NULL;
    */
  }
#endif
  if (failed) {
    writelog("xlogin ended with failure");
    exit(EXIT_FAILURE);
  }
  writelog("xlogin ended");
  exit(EXIT_SUCCESS);
}

//test unit
#ifdef TESTUNIT
 static bool always_valid(const char *const c) {
  return true;
}

 static bool test__read_valid_line_from_file(char buf[],const char *const results[],bool (*validate)(const char *const)) {
   FILE* stream=fmemopen(buf,strlen(buf),"r");//simular stream read only
    char line[MAX_PATH];
    short int i=0;
    bool success=false, eof=false;
    do {
      success=read_valid_line_from_file(&stream, "buffer", (*validate), line);
      if (!success) {
	writelog("Error getting valid line from sessionrc file");
	return false;
      } else {
	//vwritelog("readed: '%s'",line);
	if (line[0]=='*') {//is EOF
	  eof=true;
	}
	if (strcmp(results[i],line)!=0) {
	  vwritelog("Error in line, got '%s' but wished '%s'",line,results[i]);
	  return false;
	}
      }
      i++;
    } while (!eof);
    //} while (results[++i]!=NULL);
    if (stream!=NULL) { fclose(stream); }
    return true;
 }

 static bool testunit(void) {
  //x==1, w==2, r==4
  //perm_str_to_octal
  {
    if (perm_str_to_octal("wx")!=3) {
      vwritelog("valor: %d ==3?",perm_str_to_octal("wx"));
      writelog("test perm_str_to_octal 1 failed");
      return false;
    }
    if (perm_str_to_octal("rx")!=5) {
      writelog("test perm_str_to_octal 2 failed");
      return false;
    }
    if (perm_str_to_octal("rwx")!=7) {
      writelog("test perm_str_to_octal 3 failed");
      return false;
    }
  }
  //perm_octal_to_str
  {
    char perm[PERMSZ]="   ";
    perm_octal_to_str(5,perm);//rx
    if (strcmp(perm,"rx")!=0) {
      writelog("test perm_octal_to_str 1 failed");
      return false;
    }
  }
  //perm_octal_to_str_ext
  {
    char perm1[PERMSZ]="---";
    const char result1[]="r-x";
    perm_octal_to_str_ext(5,perm1);//rx
    if (strcmp(perm1,result1)!=0) {
      vwritelog("test perm_octal_to_str_ext 1 failed Got '%s' but hope '%s'",perm1,result1);
      return false;
    }
    char perm2[PERMSZ]="---";
    const char result2[]="rw-";
    perm_octal_to_str_ext(6,perm2);//rw
    if (strcmp(perm2,result2)!=0) {
      vwritelog("test perm_octal_to_str_ext 2 failed. Got '%s' but hope '%s'",perm2,result2);
      return false;
    }
  }
  //test_perms
  {
    mode_t perms1=S_IRWXU | S_IRGRP | S_IXGRP;//750
    mode_t perms2=S_IRUSR | S_IRGRP | S_IROTH;//444
    mode_t perms3=S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;//664
    mode_t perms4=S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;//644
    char test1[FPERMSZ]="---rwxr-x---";//750
    if (!(test_perms(perms1,test1) && !test_perms(perms2,test1) && !test_perms(perms3,test1) && !test_perms(perms4,test1))) {
      writelog("test_perms 1 failed");
      return false;
    }
    char test2[FPERMSZ]="---r--r--r--";//444
    if (!(!test_perms(perms1,test2) && test_perms(perms2,test2) && !test_perms(perms3,test2) && !test_perms(perms4,test2))) {
      writelog("test_perms 2 failed");
      return false;
    }
    char test3[FPERMSZ]="---r##r##r--";// >=4 >=4 4
    if (!(!test_perms(perms1,test3) && test_perms(perms2,test3) && test_perms(perms3,test3) && test_perms(perms4,test3))) {
      writelog("test_perms 3 failed");
      return false;
    }
    char test4[FPERMSZ]="---rw#r-####";// >=6 4,5 >=0
    if (!(test_perms(perms1,test4) && !test_perms(perms2,test4) && !test_perms(perms3,test4) && test_perms(perms4,test4))) {
      writelog("test_perms 4 failed");
      return false;
    }
  }
  //argv2str
  {
    char strchmod[CHMODSZ];
    //
    memset(strchmod,0,CHMODSZ);
    size_t perm_argv_array_sz1=4;
    char* perm_argv_array1[4]={ "u-srwx", "g-srwx", "o-trwx" , NULL };
    const char test1[]="u-srwx,g-srwx,o-trwx";
    argv2str(perm_argv_array1, perm_argv_array_sz1, ",", strchmod, CHMODSZ);
    if (strcmp(strchmod,test1)) {
      vwritelog("test perm_str_to_chmod_cmd 1 failed. Got '%s' but hope '%s'",strchmod,test1);
      return false;
    }
    //
    memset(strchmod,0,CHMODSZ);
    size_t perm_argv_array_sz2=2;
    char* perm_argv_array2[2]={ "u-srwx" , NULL };
    const char test2[]="u-srwx";
    argv2str(perm_argv_array2, perm_argv_array_sz2, ",", strchmod, CHMODSZ);
    if (strcmp(strchmod,test2)) {
      vwritelog("test perm_str_to_chmod_cmd 2 failed. Got '%s' but hope '%s'",strchmod,test2);
      return false;
    }
    //
    //char strchmod3[20];
    //memset(strchmod,0,20);
    size_t perm_argv_array_sz3=4;
    char* perm_argv_array3[4]={ "aaaa", "bbbbbb" ,"ccc" , NULL };
    const char test3[]="aaaaxxxbbbbbbxxxccc";
    const size_t sz=sizeof(test3);
    char strchmod3[sz];//using variadic
    memset(strchmod,0,sz);
    argv2str(perm_argv_array3, perm_argv_array_sz3, "xxx", strchmod3, sizeof(strchmod3));
    if (strcmp(strchmod3,test3)) {
      vwritelog("test perm_str_to_chmod_cmd 3 failed. Got '%s' but hope '%s'",strchmod3,test3);
      return false;
    }
    //
  }
  //perm_str_to_chmod_cmd
  {
    char strchmod[CHMODSZ];
    //
    memset(strchmod,0,CHMODSZ);
    perm_str_to_chmod_cmd("---rw-r--r--",strchmod);//strchmod is converse
    const char test1[]="u-sx,g-swx,o-twx";
    if (strcmp(strchmod,test1)!=0) {
      vwritelog("test perm_str_to_chmod_cmd 1 failed. Got '%s' but hope '%s'",strchmod,test1);
      return false;
    }
    //
    memset(strchmod,0,CHMODSZ);
    perm_str_to_chmod_cmd("rw-rwxr-xr-x",strchmod);//strchmod is converse
    const char test2[]="g-w,o-tw";
    if (strcmp(strchmod,test2)!=0) {
      vwritelog("test perm_str_to_chmod_cmd 2 failed. Got '%s' but hope '%s'",strchmod,test2);
      return false;
    }
    //
    memset(strchmod,0,CHMODSZ);
    perm_str_to_chmod_cmd("--xrwxrwxrwx",strchmod);//strchmod is converse
    const char test3[]="u-s,g-s";
    if (strcmp(strchmod,test3)!=0) {
      vwritelog("test perm_str_to_chmod_cmd 3 failed. Got '%s' but hope '%s'",strchmod,test3);
      return false;
    }
  }
  //str 2 argv : read_valid_line_from_file
  {
    //require #include <stdio.h> y usa fmemopen para crear un stream desde un string y poder simular una lectura de un stream

    //got_valid_line de start_session: lee las lineas descartando comentadas y lee como ultima linea la que empieza con '*' (exec line) requerida
    char buf1[] = "/usr/bin/xterm -rv\n*twm\n%";//obtengo '%' y EOF al final; pero no se lee porque llego solo hasta la linea '*'
    const char *const results1[]={"/usr/bin/xterm -rv","*twm",NULL};
    if (!test__read_valid_line_from_file(buf1,results1,valid_not_commented_or_null_line)) {//no lee '%' y por eso no esta en results array
      writelog("test__read_valid_line_from_file: test1 failed");
      return false;
    }
    //
    char buf2[] = "/usr/bin/xterm -rv\n*twm\n";//obtengo \n y EOF al final
    if (!test__read_valid_line_from_file(buf2,results1,valid_not_commented_or_null_line)) {
      writelog("test__read_valid_line_from_file: test2 failed");
      return false;
    }

    char buf3[] = "/usr/bin/xterm -rv\n*twm";//obtengo solo EOF al final y no es un error
    if (!test__read_valid_line_from_file(buf3,results1,valid_not_commented_or_null_line)) {//this test have to fail, not allowed forgot last commented line
      writelog("test__read_valid_line_from_file: test3 failed");
      return false;
    }

    char buf4[] = " /usr/bin/xterm -rv\n*twm ";//obtengo solo EOF al final y no es un error
    if (!test__read_valid_line_from_file(buf4,results1,valid_not_commented_or_null_line)) {//this test have to fail, not allowed forgot last commented line
      writelog("test__read_valid_line_from_file: test4 failed");
      return false;
    }

    char buf5[] = "#comm1\n/usr/bin/xterm -rv\n#comm2\n*twm\n%";//obtengo '%' y EOF al final; pero no se lee porque llego solo hasta la linea '*'
    const char *const results5[]={"/usr/bin/xterm -rv","*twm",NULL};
    if (!test__read_valid_line_from_file(buf5,results5,valid_not_commented_or_null_line)) {//no lee '%' y por eso no esta en results array
      writelog("test__read_valid_line_from_file: test5 failed");
      return false;
    }

    char buf6[] = "#comm1\n/usr/bin/xterm -rv\n#comm2\ntwm\n%";//obtengo '%' y EOF al final; pero no se lee porque llego solo hasta la linea '*'
    const char *const results6[]={"/usr/bin/xterm -rv","twm","%",NULL};
    if (test__read_valid_line_from_file(buf6,results6,valid_not_commented_or_null_line)) {//no lee '%' y por eso no esta en results array
      writelog("test__read_valid_line_from_file: test6 failed");
      return false;
    } else {
      writelog("Ignore previous errors!");
    }

    //test__read_valid_line_from_file(buf4,results4,always_valid)

    //char buf1[] = "var1=value1\nvar2=value2\n";//obtengo \n y EOF al final
    //char buf2[] = "var1=value1\nvar2=value2";//obtengo solo EOF al final
  }
  //test basename
  {
    char* dir="/tmp/.X11/X0";
    //vwritelog("%s",dir);
    char* dircp=strdup(dir);//required, don't handle static arrays
    char* cdir=dirname(dircp);
    //vwritelog("%s",cdir);
    char* cdircp=strdup(cdir);
    char* cdir2=dirname(cdircp);
    //vwritelog("%s",cdir2);
    if (strcmp(dir,cdir)==0) {
      vwritelog("strings must not be equal '%s' != '%s'",cdir,dir);
      return false;
    }
    if (strcmp(cdir,cdir2)==0) {//si no hago copias, la comparacion falla siempre
      vwritelog("strings must not be equal '%s' != '%s'",cdir,cdir2);
      return false;
    }
    free(dircp);free(cdircp);
  }
  writelog("unittest success");
  return true;
}
#endif
