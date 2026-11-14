/* licd: demo program for the Basilisk interface (see README.md here).
 *
 * A small licence daemon: it reads a configuration file, checks a licence
 * key, decodes its obfuscated strings and talks to an activation server.
 * The code is written the way Ghidra's decompiler prints it (Ghidra's type
 * names, local names such as local_28 and iVar1), so that the text between a
 * function's first line and its closing brace is shown as the "decompiled"
 * C, and the DWARF line table of the compiled program maps each line to the
 * instructions it became. Everything above the first function is a header
 * that the generator skips.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/utsname.h>

typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned int undefined4;
typedef unsigned long undefined8;

typedef struct config {
  char server[128];
  int port;
  int interval;
  char key[64];
  char user[64];
  int verbose;
} config_t;

typedef struct buffer {
  char *data;
  ulong len;
  ulong cap;
} buffer_t;

typedef struct rc4_state {
  byte s[256];
  byte i;
  byte j;
} rc4_state_t;

config_t g_config;
uint crc_table[256];
int crc_table_ready;
int g_log_level = 1;
int g_running = 1;
long g_last_contact;
rc4_state_t g_rc4;

byte s_banner_enc[24] = {0x0e, 0x0b, 0x01, 0x06, 0x48, 0x5c, 0x46, 0x5d, 0x55, 0x00};
byte s_activate_enc[16] = {0x23, 0x21, 0x36, 0x2b, 0x34, 0x23, 0x36, 0x27, 0x00};
byte s_heartbeat_enc[16] = {0x2a, 0x27, 0x23, 0x30, 0x36, 0x20, 0x27, 0x23, 0x36, 0x00};
const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char *level_names[4] = {"debug", "info", "warn", "error"};

void log_msg(int param_1,char *param_2,...)
{
  va_list local_28;

  if (g_log_level <= param_1) {
    va_start(local_28,param_2);
    fprintf(stderr,"[licd] %s: ",level_names[param_1 & 3]);
    vfprintf(stderr,param_2,local_28);
    fputc(10,stderr);
    va_end(local_28);
  }
  return;
}

void fatal(char *param_1)
{
  log_msg(3,"%s",param_1);
  exit(1);
}

void * xmalloc(ulong param_1)
{
  void *pvVar1;

  pvVar1 = malloc(param_1);
  if (pvVar1 == (void *)0x0) {
    fatal("out of memory");
  }
  return pvVar1;
}

char * xstrdup(char *param_1)
{
  ulong uVar1;
  char *pcVar2;

  uVar1 = strlen(param_1);
  pcVar2 = (char *)xmalloc(uVar1 + 1);
  memcpy(pcVar2,param_1,uVar1 + 1);
  return pcVar2;
}

ulong safe_copy(char *param_1,char *param_2,ulong param_3)
{
  ulong uVar1;

  uVar1 = 0;
  if (param_3 != 0) {
    while ((uVar1 < param_3 - 1 && (param_2[uVar1] != '\0'))) {
      param_1[uVar1] = param_2[uVar1];
      uVar1 = uVar1 + 1;
    }
    param_1[uVar1] = '\0';
  }
  return uVar1;
}

char * trim(char *param_1)
{
  ulong uVar1;
  char *pcVar2;

  while ((*param_1 == ' ' || (*param_1 == '\t'))) {
    param_1 = param_1 + 1;
  }
  uVar1 = strlen(param_1);
  pcVar2 = param_1 + uVar1;
  while ((param_1 < pcVar2 &&
         (((pcVar2[-1] == ' ' || (pcVar2[-1] == '\t')) || (pcVar2[-1] == '\n'))))) {
    pcVar2 = pcVar2 + -1;
  }
  *pcVar2 = '\0';
  return param_1;
}

void buffer_init(buffer_t *param_1,ulong param_2)
{
  param_1->data = (char *)xmalloc(param_2);
  param_1->len = 0;
  param_1->cap = param_2;
  return;
}

void buffer_append(buffer_t *param_1,void *param_2,ulong param_3)
{
  ulong uVar1;
  char *pcVar2;

  uVar1 = param_1->cap;
  if (uVar1 < param_1->len + param_3) {
    do {
      uVar1 = uVar1 * 2;
    } while (uVar1 < param_1->len + param_3);
    pcVar2 = (char *)realloc(param_1->data,uVar1);
    if (pcVar2 == (char *)0x0) {
      fatal("out of memory");
    }
    param_1->data = pcVar2;
    param_1->cap = uVar1;
  }
  memcpy(param_1->data + param_1->len,param_2,param_3);
  param_1->len = param_1->len + param_3;
  return;
}

void buffer_free(buffer_t *param_1)
{
  free(param_1->data);
  param_1->data = (char *)0x0;
  param_1->len = 0;
  param_1->cap = 0;
  return;
}

void xor_decode(byte *param_1,byte param_2)
{
  byte bVar1;

  bVar1 = *param_1;
  while (bVar1 != 0) {
    *param_1 = bVar1 ^ param_2;
    param_1 = param_1 + 1;
    bVar1 = *param_1;
  }
  return;
}

void crc32_init_table(void)
{
  uint uVar1;
  uint uVar2;
  int iVar3;

  for (uVar2 = 0; uVar2 < 0x100; uVar2 = uVar2 + 1) {
    uVar1 = uVar2;
    for (iVar3 = 0; iVar3 < 8; iVar3 = iVar3 + 1) {
      if ((uVar1 & 1) == 0) {
        uVar1 = uVar1 >> 1;
      }
      else {
        uVar1 = uVar1 >> 1 ^ 0xedb88320;
      }
    }
    crc_table[uVar2] = uVar1;
  }
  crc_table_ready = 1;
  return;
}

uint crc32(byte *param_1,ulong param_2)
{
  uint uVar1;
  ulong uVar2;

  if (crc_table_ready == 0) {
    crc32_init_table();
  }
  uVar1 = 0xffffffff;
  for (uVar2 = 0; uVar2 < param_2; uVar2 = uVar2 + 1) {
    uVar1 = crc_table[(param_1[uVar2] ^ uVar1) & 0xff] ^ uVar1 >> 8;
  }
  return ~uVar1;
}

uint hash_djb2(char *param_1)
{
  uint uVar1;
  char cVar2;

  uVar1 = 0x1505;
  cVar2 = *param_1;
  while (cVar2 != '\0') {
    uVar1 = uVar1 * 0x21 + (int)cVar2;
    param_1 = param_1 + 1;
    cVar2 = *param_1;
  }
  return uVar1;
}

void rc4_init(rc4_state_t *param_1,byte *param_2,ulong param_3)
{
  byte bVar1;
  uint uVar2;
  byte bVar3;

  for (uVar2 = 0; uVar2 < 0x100; uVar2 = uVar2 + 1) {
    param_1->s[uVar2] = (byte)uVar2;
  }
  bVar3 = 0;
  for (uVar2 = 0; uVar2 < 0x100; uVar2 = uVar2 + 1) {
    bVar1 = param_1->s[uVar2];
    bVar3 = bVar3 + bVar1 + param_2[uVar2 % param_3];
    param_1->s[uVar2] = param_1->s[bVar3];
    param_1->s[bVar3] = bVar1;
  }
  param_1->i = 0;
  param_1->j = 0;
  return;
}

void rc4_crypt(rc4_state_t *param_1,byte *param_2,ulong param_3)
{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  ulong uVar4;

  bVar2 = param_1->i;
  bVar3 = param_1->j;
  for (uVar4 = 0; uVar4 < param_3; uVar4 = uVar4 + 1) {
    bVar2 = bVar2 + 1;
    bVar1 = param_1->s[bVar2];
    bVar3 = bVar3 + bVar1;
    param_1->s[bVar2] = param_1->s[bVar3];
    param_1->s[bVar3] = bVar1;
    param_2[uVar4] = param_2[uVar4] ^ param_1->s[(byte)(param_1->s[bVar2] + bVar1)];
  }
  param_1->i = bVar2;
  param_1->j = bVar3;
  return;
}

ulong base64_encode(byte *param_1,ulong param_2,char *param_3)
{
  uint uVar1;
  ulong uVar2;
  ulong uVar3;

  uVar3 = 0;
  for (uVar2 = 0; uVar2 < param_2; uVar2 = uVar2 + 3) {
    uVar1 = (uint)param_1[uVar2] << 0x10;
    if (uVar2 + 1 < param_2) {
      uVar1 = uVar1 | (uint)param_1[uVar2 + 1] << 8;
    }
    if (uVar2 + 2 < param_2) {
      uVar1 = uVar1 | param_1[uVar2 + 2];
    }
    param_3[uVar3] = b64_alphabet[uVar1 >> 0x12 & 0x3f];
    param_3[uVar3 + 1] = b64_alphabet[uVar1 >> 0xc & 0x3f];
    param_3[uVar3 + 2] = (uVar2 + 1 < param_2) ? b64_alphabet[uVar1 >> 6 & 0x3f] : '=';
    param_3[uVar3 + 3] = (uVar2 + 2 < param_2) ? b64_alphabet[uVar1 & 0x3f] : '=';
    uVar3 = uVar3 + 4;
  }
  param_3[uVar3] = '\0';
  return uVar3;
}

int b64_value(char param_1)
{
  char *pcVar1;

  if (param_1 == '=') {
    return 0;
  }
  pcVar1 = strchr(b64_alphabet,(int)param_1);
  if (pcVar1 == (char *)0x0) {
    return -1;
  }
  return (int)pcVar1 - (int)b64_alphabet;
}

long base64_decode(char *param_1,byte *param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  long lVar5;

  lVar5 = 0;
  while (*param_1 != '\0') {
    iVar1 = b64_value(*param_1);
    iVar2 = b64_value(param_1[1]);
    iVar3 = b64_value(param_1[2]);
    iVar4 = b64_value(param_1[3]);
    if ((((iVar1 < 0) || (iVar2 < 0)) || (iVar3 < 0)) || (iVar4 < 0)) {
      return -1;
    }
    param_2[lVar5] = (byte)(iVar1 << 2) | (byte)(iVar2 >> 4);
    if (param_1[2] != '=') {
      param_2[lVar5 + 1] = (byte)(iVar2 << 4) | (byte)(iVar3 >> 2);
    }
    if (param_1[3] != '=') {
      param_2[lVar5 + 2] = (byte)(iVar3 << 6) | (byte)iVar4;
    }
    lVar5 = lVar5 + 3;
    param_1 = param_1 + 4;
  }
  return lVar5;
}

int parse_config_line(config_t *param_1,char *param_2)
{
  char *pcVar1;
  char *pcVar2;
  int iVar3;

  pcVar1 = strchr(param_2,0x3d);
  if (pcVar1 == (char *)0x0) {
    return -1;
  }
  *pcVar1 = '\0';
  pcVar2 = trim(param_2);
  pcVar1 = trim(pcVar1 + 1);
  iVar3 = strcmp(pcVar2,"server");
  if (iVar3 == 0) {
    safe_copy(param_1->server,pcVar1,0x80);
  }
  else if (iVar3 = strcmp(pcVar2,"port"), iVar3 == 0) {
    param_1->port = atoi(pcVar1);
  }
  else if (iVar3 = strcmp(pcVar2,"interval"), iVar3 == 0) {
    param_1->interval = atoi(pcVar1);
  }
  else if (iVar3 = strcmp(pcVar2,"key"), iVar3 == 0) {
    safe_copy(param_1->key,pcVar1,0x40);
  }
  else if (iVar3 = strcmp(pcVar2,"user"), iVar3 == 0) {
    safe_copy(param_1->user,pcVar1,0x40);
  }
  else {
    log_msg(2,"unknown option \'%s\'",pcVar2);
    return -1;
  }
  return 0;
}

int load_config(char *param_1,config_t *param_2)
{
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  int iVar3;
  char local_218 [512];

  __stream = fopen(param_1,"r");
  if (__stream == (FILE *)0x0) {
    log_msg(3,"cannot open %s",param_1);
    return -1;
  }
  iVar3 = 0;
  while (pcVar1 = fgets(local_218,0x200,__stream), pcVar1 != (char *)0x0) {
    iVar3 = iVar3 + 1;
    pcVar1 = trim(local_218);
    if ((*pcVar1 != '\0') && (*pcVar1 != '#')) {
      iVar2 = parse_config_line(param_2,pcVar1);
      if (iVar2 != 0) {
        log_msg(2,"%s:%d: ignored",param_1,iVar3);
      }
    }
  }
  fclose(__stream);
  return 0;
}

void config_defaults(config_t *param_1)
{
  memset(param_1,0,0x14c);
  safe_copy(param_1->server,"activate.example.net",0x80);
  param_1->port = 0x1bb;
  param_1->interval = 0x3c;
  return;
}

int validate_key(char *param_1)
{
  ulong uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;

  uVar1 = strlen(param_1);
  if (uVar1 != 0x18) {
    return 0;
  }
  for (iVar4 = 0; iVar4 < 0x18; iVar4 = iVar4 + 1) {
    if (((iVar4 + 1) % 5 == 0) && (param_1[iVar4] != '-')) {
      return 0;
    }
  }
  uVar2 = crc32((byte *)param_1,0x13);
  uVar3 = (uint)strtoul(param_1 + 0x14,(char **)0x0,0x10);
  return (int)((uVar2 & 0xffff) == uVar3);
}

int check_debugger(void)
{
  pid_t pVar1;
  char *pcVar2;

  pVar1 = getppid();
  if (pVar1 == 1) {
    return 0;
  }
  pcVar2 = getenv("DYLD_INSERT_LIBRARIES");
  if (pcVar2 != (char *)0x0) {
    return 1;
  }
  pcVar2 = getenv("LICD_TRACE");
  return (int)(pcVar2 != (char *)0x0);
}

void decode_strings(void)
{
  xor_decode(s_banner_enc,0x42);
  xor_decode(s_activate_enc,0x42);
  xor_decode(s_heartbeat_enc,0x42);
  return;
}

int connect_server(char *param_1,int param_2)
{
  int iVar1;
  int iVar2;
  struct addrinfo *local_68;
  struct addrinfo local_60;
  char local_28 [16];

  memset(&local_60,0,0x30);
  local_60.ai_family = 0;
  local_60.ai_socktype = 1;
  snprintf(local_28,0x10,"%d",param_2);
  iVar1 = getaddrinfo(param_1,local_28,&local_60,&local_68);
  if (iVar1 != 0) {
    log_msg(3,"resolve %s: %s",param_1,gai_strerror(iVar1));
    return -1;
  }
  iVar1 = socket(local_68->ai_family,local_68->ai_socktype,local_68->ai_protocol);
  if (iVar1 < 0) {
    freeaddrinfo(local_68);
    return -1;
  }
  iVar2 = connect(iVar1,local_68->ai_addr,local_68->ai_addrlen);
  freeaddrinfo(local_68);
  if (iVar2 < 0) {
    close(iVar1);
    return -1;
  }
  return iVar1;
}

int send_all(int param_1,char *param_2,ulong param_3)
{
  long lVar1;

  while (param_3 != 0) {
    lVar1 = send(param_1,param_2,param_3,0);
    if (lVar1 < 1) {
      return -1;
    }
    param_2 = param_2 + lVar1;
    param_3 = param_3 - lVar1;
  }
  return 0;
}

long recv_line(int param_1,char *param_2,ulong param_3)
{
  long lVar1;
  ulong uVar2;
  char local_19;

  uVar2 = 0;
  while (uVar2 < param_3 - 1) {
    lVar1 = recv(param_1,&local_19,1,0);
    if (lVar1 < 1) {
      return -1;
    }
    if (local_19 == '\n') break;
    param_2[uVar2] = local_19;
    uVar2 = uVar2 + 1;
  }
  param_2[uVar2] = '\0';
  return (long)uVar2;
}

void build_request(buffer_t *param_1,char *param_2,config_t *param_3)
{
  int iVar1;
  char local_118 [256];

  iVar1 = snprintf(local_118,0x100,"%s user=%s key=%s ts=%ld\n",param_2,param_3->user,
                   param_3->key,time((time_t *)0x0));
  buffer_append(param_1,local_118,(long)iVar1);
  return;
}

int cmd_sysinfo(int param_1)
{
  int iVar1;
  struct utsname local_520;
  char local_120 [256];

  iVar1 = uname(&local_520);
  if (iVar1 != 0) {
    return -1;
  }
  iVar1 = snprintf(local_120,0x100,"sysinfo %s %s %s\n",local_520.sysname,local_520.release,
                   local_520.machine);
  return send_all(param_1,local_120,(long)iVar1);
}

int cmd_sleep(char *param_1)
{
  int iVar1;

  iVar1 = atoi(param_1);
  if ((iVar1 < 1) || (0xe10 < iVar1)) {
    log_msg(2,"bad interval %s",param_1);
    return -1;
  }
  g_config.interval = iVar1;
  return 0;
}

int cmd_status(int param_1)
{
  int iVar1;
  char local_98 [128];

  iVar1 = snprintf(local_98,0x80,"status ok last=%ld\n",g_last_contact);
  return send_all(param_1,local_98,(long)iVar1);
}

int handle_command(int param_1,char *param_2)
{
  int iVar1;

  iVar1 = strncmp(param_2,"sysinfo",7);
  if (iVar1 == 0) {
    return cmd_sysinfo(param_1);
  }
  iVar1 = strncmp(param_2,"sleep ",6);
  if (iVar1 == 0) {
    return cmd_sleep(param_2 + 6);
  }
  iVar1 = strncmp(param_2,"status",6);
  if (iVar1 == 0) {
    return cmd_status(param_1);
  }
  iVar1 = strncmp(param_2,"quit",4);
  if (iVar1 == 0) {
    g_running = 0;
    return 0;
  }
  log_msg(2,"unknown command \'%s\'",param_2);
  return -1;
}

int activate(config_t *param_1)
{
  int iVar1;
  int iVar2;
  long lVar3;
  buffer_t local_240;
  char local_228 [512];

  iVar1 = connect_server(param_1->server,param_1->port);
  if (iVar1 < 0) {
    log_msg(3,"cannot reach %s:%d",param_1->server,param_1->port);
    return -1;
  }
  buffer_init(&local_240,0x100);
  build_request(&local_240,(char *)s_activate_enc,param_1);
  iVar2 = send_all(iVar1,local_240.data,local_240.len);
  buffer_free(&local_240);
  if ((iVar2 == 0) && (lVar3 = recv_line(iVar1,local_228,0x200), -1 < lVar3)) {
    iVar2 = strncmp(local_228,"OK",2);
    close(iVar1);
    return -(uint)(iVar2 != 0);
  }
  close(iVar1);
  return -1;
}

void jitter_sleep(int param_1)
{
  int iVar1;

  iVar1 = rand();
  sleep(param_1 + iVar1 % (param_1 / 4 + 1));
  return;
}

int heartbeat(config_t *param_1)
{
  int iVar1;
  int iVar2;
  long lVar3;
  buffer_t local_240;
  char local_228 [512];

  iVar1 = connect_server(param_1->server,param_1->port);
  if (iVar1 < 0) {
    return -1;
  }
  buffer_init(&local_240,0x100);
  build_request(&local_240,(char *)s_heartbeat_enc,param_1);
  iVar2 = send_all(iVar1,local_240.data,local_240.len);
  buffer_free(&local_240);
  while ((iVar2 == 0 && (lVar3 = recv_line(iVar1,local_228,0x200), 0 < lVar3))) {
    g_last_contact = time((time_t *)0x0);
    iVar2 = handle_command(iVar1,local_228);
    if (g_running == 0) break;
  }
  close(iVar1);
  return 0;
}

void run_loop(config_t *param_1)
{
  int iVar1;
  int iVar2;

  iVar2 = 0;
  while (g_running != 0) {
    iVar1 = heartbeat(param_1);
    if (iVar1 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = iVar2 + 1;
      log_msg(2,"heartbeat failed (%d)",iVar2);
    }
    if (g_running == 0) break;
    jitter_sleep(param_1->interval << ((byte)iVar2 & 3));
  }
  return;
}

void usage(char *param_1)
{
  fprintf(stderr,"usage: %s [-v] [-c config] [-k key]\n",param_1);
  exit(2);
}

int parse_args(int param_1,char **param_2,config_t *param_3,char **param_4)
{
  int iVar1;

  while (iVar1 = getopt(param_1,param_2,"vc:k:"), iVar1 != -1) {
    if (iVar1 == 0x76) {
      param_3->verbose = 1;
      g_log_level = 0;
    }
    else if (iVar1 == 99) {
      *param_4 = optarg;
    }
    else if (iVar1 == 0x6b) {
      safe_copy(param_3->key,optarg,0x40);
    }
    else {
      usage(*param_2);
    }
  }
  return 0;
}

void print_banner(void)
{
  char local_58 [64];

  safe_copy(local_58,(char *)s_banner_enc,0x40);
  log_msg(1,"%s starting (pid %d)",local_58,getpid());
  return;
}

int main(int param_1,char **param_2)
{
  int iVar1;
  char *local_20;

  local_20 = "/etc/licd.conf";
  config_defaults(&g_config);
  parse_args(param_1,param_2,&g_config,&local_20);
  decode_strings();
  print_banner();
  iVar1 = check_debugger();
  if (iVar1 != 0) {
    log_msg(3,"tracing detected");
    return 3;
  }
  load_config(local_20,&g_config);
  iVar1 = validate_key(g_config.key);
  if (iVar1 == 0) {
    fatal("invalid licence key");
  }
  srand((uint)time((time_t *)0x0) ^ hash_djb2(g_config.user));
  rc4_init(&g_rc4,(byte *)g_config.key,0x18);
  iVar1 = activate(&g_config);
  if (iVar1 != 0) {
    log_msg(3,"activation failed");
    return 1;
  }
  run_loop(&g_config);
  return 0;
}
