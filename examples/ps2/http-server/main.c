#include "mongoose.h"

#define NEWLIB_PORT_AWARE

#include "network.h"

#include <debug.h>
#include <iopcontrol.h>
#include <sbv_patches.h>
#include <sifrpc.h>
#include <loadfile.h>
#include <libhdd.h>
#include <fileXio.h>
#include <fileXio_rpc.h>
#include <sio.h>
const char *index_html =
    "<!DOCTYPE html>\
<html>\
<head>\
	<title>Hello, this is being served on my PS2!</title>\
</head>\
<body>\
	<h1>Hello, this is being served on my PS2!</h1>\
	<p>It's a bit slow, but it works!</p>\
  <p>COP0 Count: %d</p>\
</body>\
</html>\
";

int fx_stat(const char* path, size_t *size, time_t *mtime)
{
  iox_stat_t stat;
  int ret = fileXioGetStat(path, &stat);
  if (ret < 0) {
    return 0;
  }
  if(size) *size = stat.size;
  if(mtime) *mtime = *((time_t*)&stat.mtime);
  return MG_FS_READ | MG_FS_WRITE | (S_ISDIR(stat.mode) ? MG_FS_DIR : 0);
}

static void fx_list(const char *dir, void (*fn)(const char *, void *),
                   void *userdata) {
  iox_dirent_t dp;
  int fd = fileXioDopen(dir);
  if (fd < 0) {
    return;
  }
  while ((fileXioDread(fd, &dp)) > 0) {
    if (!strcmp(dp.name, ".") || !strcmp(dp.name, "..")) continue;
    fn(dp.name, userdata);
  }
  fileXioDclose(fd);
}


static void* fx_open(const char *path, int flags) {
  int fd = fileXioOpen(path, flags, 0666);
  if (fd < 0) {
    return NULL;
  }
  return (void*)fd;
}

static void fx_close(void* fd) {
   fileXioClose((int)fd);
}

static size_t fx_read(void* fd, void* buf, size_t size) {
  return fileXioRead((int)fd, buf, size);
}

static size_t fx_seek(void* fd, size_t offset) {
  return fileXioLseek((int)fd, offset, SEEK_SET);
}

static size_t fx_write(void* fd, const void* buf, size_t size) {
  return fileXioWrite((int)fd, buf, size);
}

static bool fx_rename(const char *src, const char *dst) {
  return fileXioRename(src, dst) == 0;
}

static bool fx_remove(const char *path) {
  return fileXioRemove(path) == 0;
}

static bool fx_mkdir(const char *path) {
  return fileXioMkdir(path, 0777);
}

struct mg_fs filexio_fs = {
  .st = &fx_stat,
  .ls = &fx_list,
  .op = &fx_open,
  .cl = &fx_close,
  .rd = &fx_read,
  .wr = &fx_write,
  .sk = &fx_seek,
  .mv = &fx_rename,
  .rm = &fx_remove,
  .mkd = &fx_mkdir,
};

u64 req_count = 0;
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    scr_printf("Got request for %.*s\n", (int) hm->uri.len, hm->uri.ptr);
    scr_printf("Request count: %d\n", ++req_count);
    if (mg_http_match_uri(hm, "/api/hello")) {  // On /api/hello requests,
      mg_http_reply(c, 200, "", "{%m:%d}\n", MG_ESC("status"),
                    1);  // Send dynamic JSON response
    } else if (mg_http_match_uri(hm, "/index.htm")) {
          u32 count = 0;
    __asm__ __volatile__("mfc0 %0, $9" : "=r"(count));
      mg_http_reply(c, 200, "", index_html, count);  // Send dynamic JSON response
    } else {                                  // For all other URIs,
      struct mg_http_serve_opts opts = {.root_dir = "pfs0:.", .fs = &filexio_fs};  // Serve files
      mg_http_serve_dir(c, hm, &opts);                         // From root_dir
    }
  }
}

extern unsigned char ps2dev9_irx[];
extern unsigned int size_ps2dev9_irx;
extern unsigned char netman_irx[];
extern unsigned int size_netman_irx;
extern unsigned char ps2ip_irx[];
extern unsigned int size_ps2ip_irx;
extern unsigned char smap_irx[];
extern unsigned int size_smap_irx;
extern unsigned char atad_irx[];
extern unsigned int size_atad_irx;
extern unsigned char iomanx_irx[];
extern unsigned int size_iomanx_irx;
extern unsigned char filexio_irx[];
extern unsigned int size_filexio_irx;
extern unsigned char hdd_irx[];
extern unsigned int size_hdd_irx;
extern unsigned char ps2fs_irx[];
extern unsigned int size_ps2fs_irx;

void loadIOPModules() {
  SifInitRpc(0);
  while (!SifIopReset("", 0)) {
  };
  while (!SifIopSync()) {
  };
  SifInitRpc(0);
  sbv_patch_enable_lmb();
  int ret = SifExecModuleBuffer(ps2dev9_irx, size_ps2dev9_irx, 0, NULL, NULL);

  // Following modules are required for network support
  scr_printf("Loaded ps2dev9.irx: %d\n", ret);
  ret = SifExecModuleBuffer(netman_irx, size_netman_irx, 0, NULL, NULL);
  scr_printf("Loaded netman.irx: %d\n", ret);
  ret = SifExecModuleBuffer(ps2ip_irx, size_ps2ip_irx, 0, NULL, NULL);
  scr_printf("Loaded ps2ip.irx: %d\n", ret);
  ret = SifExecModuleBuffer(smap_irx, size_smap_irx, 0, NULL, NULL);
  scr_printf("Loaded smap.irx: %d\n", ret);
  ret = SifExecModuleBuffer(atad_irx, size_atad_irx, 0, NULL, NULL);
  scr_printf("Loaded ps2atad.irx: %d\n", ret);
  ret = SifExecModuleBuffer(iomanx_irx, size_iomanx_irx, 0, NULL, NULL);

  // Following modules are required for HDD support
  scr_printf("Loaded iomanx.irx: %d\n", ret);
  ret = SifExecModuleBuffer(filexio_irx, size_filexio_irx, 0, NULL, NULL);
  scr_printf("Loaded filexio.irx: %d\n", ret);
  ret = SifExecModuleBuffer(hdd_irx, size_hdd_irx, 0, NULL, NULL);
  scr_printf("Loaded ps2hdd.irx: %d\n", ret);
  ret = SifExecModuleBuffer(ps2fs_irx, size_ps2fs_irx, 0, NULL, NULL);
  scr_printf("Loaded ps2fs.irx: %d\n", ret);

  fileXioInit();
  network_init();
  return;
}

int main(int argc, char *argv[]) {
  init_scr();

  scr_setCursor(0);
  loadIOPModules();
  scr_printf("Starting mongoose version %s\n", MG_VERSION);

  int ret;
  if((ret = fileXioMount("pfs0:", "hdd0:WWW", 0)) < 0)
  {
    scr_printf("Failed to mount pfs1 (%d)\n",ret);
  }

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);                                      // Init manager
  mg_http_listen(&mgr, "http://0.0.0.0:80", fn, &mgr);  // Setup listener
  for (;;) mg_mgr_poll(&mgr, 1000);                       // Event loop
  mg_mgr_free(&mgr);                                      // Cleanup
  return 0;
}
