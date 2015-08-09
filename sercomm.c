/*
 * sercomm utility to detect and flash firmware to a Linksys WAG160Nv2.
 *
 * Based on information from the the upslug2 tool
 * http://www.nslu2-linux.org/wiki/Main/UpSlug2
 * 
 * The firmware file must contain a bootloader section
 * with a pid in order to be able to compare the hardware id.
 *
 * compile this file under Linux: make sercomm
 * You  must be root to run it.
 *
 * There is no Windows version of it, please don't ask for a port
 * (just do it yourself).
 *
 * copyright (c) Joerg Albert <jal2 at gmx.de> , 2011
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#define _GNU_SOURCE /* to get sighandler_t from signal.h */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <endian.h>

/* fixed ethernet type for all packets */
#define ETH_P_SERCOMM 0x8888

/* offset of "CFE1CFE1" in a firmware file */
#define CFE_MAGIC_OFFSET 0x4e0

/* max. size of a firmware file */
#define MAX_FW_SIZE ((unsigned long int)(4*1024*1024))

#define PID_MAGIC "sErCoMm"
#define PID2_MAGIC "seRcOmM"
#define PID_OFFSET 0xff80
#define PID_MAGIC_LEN 7
struct pid_s {
  char magic[PID_MAGIC_LEN]; /* PID*_MAGIC */
  char reserved[4];
  char hw_id[34]; /* hardware id: */
  char annex; /* annex A or B */
  unsigned char function; /* 1 bridge, 3 multi-pvc */
  char company[2]; /* cisco == 08 */
  char reserved2[8];
  unsigned char version[2]; /* major == version[0]>>4),
                               minor == version[0] & 0xf,
                               subver == version[1] */
  char reserved3[4];
  char magic2[PID_MAGIC_LEN]; /* PID*_MAGIC */
};

/* minimum pid2 offset from the begin of the firmware file */
#define MIN_PID2_OFFSET 0x200000

/* max. number of bytes in a payload */
#define MAX_PAYLOAD_LEN 0x200

/* max. size of a firmware file */
#define MAX_FW_LEN 0x3e0000

#define err(fmt, __args__...) fprintf(stderr, "#ERR %s: " fmt "\n", __FUNCTION__, ##__args__ )
#define dbg(fmt, __args__...)					\
  do {								\
    if (debug)							\
      printf("#DBG %s: " fmt "\n", __FUNCTION__, ##__args__ );	\
  } while (0)

static int debug = 0;
static unsigned char own_mac[ETH_ALEN]; /* own mac address */

static void hexdump(void *addr, int len)
{
  unsigned char *c = addr;
  while (len > 0) {
    printf(" %02x", *c);
    c++;
    len--;
  }
}

static void usage(const char *name)
{

  printf("Download a firmware into a Linksys WAG160N v2\n\n");
  printf("1) Power off the device\n");
  printf("2) Press the reset button\n");
  printf("3) Power on the device while holding the reset button pressed\n");
  printf("4) Wait until the power LED flashes red/green, you may release the reset button then.\n");
  printf("   The device is in download mode now.\n");
  printf("5) Call %s [-v] <ethernet device name> [<firmware file>]\n", name);
  printf("   if <firmware file> is missing only the devices found are dumped\n");
  printf("   e.g.:\n");
  printf("    dump all devices connected to eth2: %s eth2\n", name);
  printf("    update a device at eth1: %s eth1 firmware\n", name);
  printf("    -v to see debugs for each packet sent/received\n");
}

typedef enum {
  HardwareInfo   = 0,
  UpgradeStart   = 1,
  UpgradeData    = 2,
  Reboot         = 3,
  UpgradeVerify  = 4,
  ReprogramStart = 5,
  InvalidType    = 0xffff,
} Cmd_e;

typedef enum {
  Ok            = 0, /* operation completed ok */
  ProtocolError = 5, /* operation not expected (UpgradeStart packet dropped) */
  SequenceError = 6, /* packet out of sequence (and ignored) */
  ProgramError  = 7, /* flash programming failed (fatal) */
  VerifyError   = 9, /* flash verification failed (fatal) */
} RetCode_e;

/* all multibyte values are in little endian */
struct hdr_s {
  unsigned char da[ETH_ALEN];
  unsigned char sa[ETH_ALEN];
  unsigned short eth_type; /* fixed to 0x8888 */
  unsigned short cmd; /* see Cmd_e */ /* offset 0xe */
  unsigned short seqno;
  unsigned short byte_off;
  unsigned short chunk_off;
  unsigned short length; /* length of following data */
} __attribute__ ((packed)); /* overall length = 0x18 */

/* sizeof of struct hdr_s */
#define HDR_SIZE sizeof(struct hdr_s)

void print_pkt(const char *str1, const char *str2, unsigned char *buf,
	       unsigned int len)
{
  struct hdr_s hdr;

  if (len < sizeof(hdr))
    return;
  
#define MAC_ADDR(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]

  memcpy(&hdr, buf, sizeof(hdr));
  printf("#DBG %s %s  da=%02x:%02x:%02x:%02x:%02x:%02x "
	 "sa=%02x:%02x:%02x:%02x:%02x:%02x eth_type=%04x cmd=%04x seqno=%04x\n",
	 str1, str2, MAC_ADDR(hdr.da), MAC_ADDR(hdr.sa), le16toh(hdr.eth_type), 
	 le16toh(hdr.cmd), le16toh(hdr.seqno));
  printf("#DBG   byte_off=%04x chunk_off=%04x length=%04x\n",
	 le16toh(hdr.byte_off), le16toh(hdr.chunk_off), le16toh(hdr.length));

#undef MAC_ADDR

  if (len > sizeof(hdr)) {
    printf("#DBG  payload 0x%lx:", len - sizeof(hdr));
    hexdump(buf+sizeof(hdr), MIN(len-sizeof(hdr), 16));
    printf("\n");
  }
}

static int SendHWInfoReq(int s, const unsigned char *mac)
{
#define HW_LEN 56
  struct hdr_s hdr;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.da, mac, ETH_ALEN);
  memcpy(hdr.sa, own_mac, ETH_ALEN);

  hdr.eth_type = htons(ETH_P_SERCOMM);
  hdr.cmd = htole16(HardwareInfo);
  hdr.length = htole16(HW_LEN); /* TODO: verify this magic number */

  if (debug) {
    print_pkt(__FUNCTION__, "", (unsigned char *)&hdr, sizeof(hdr));
  }
  return send(s, &hdr, sizeof(hdr), 0) < 0;
}

static int SendReboot(int s, const unsigned char *mac)
{
  struct hdr_s hdr;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.da, mac, ETH_ALEN);
  memcpy(hdr.sa, own_mac, ETH_ALEN);
  hdr.eth_type = htons(ETH_P_SERCOMM);
  hdr.cmd = htole16(Reboot);

  if (debug) {
    print_pkt(__FUNCTION__, "", (unsigned char *)&hdr, sizeof(hdr));
  }

  return send(s, &hdr, sizeof(hdr), 0) < 0;
}

static int SendUpgradeStart(int s, const unsigned char *mac,
			    unsigned short seqno)
{
  struct hdr_s hdr;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.da, mac, ETH_ALEN);
  memcpy(hdr.sa, own_mac, ETH_ALEN);
  hdr.eth_type = htons(ETH_P_SERCOMM);
  hdr.cmd = htole16(UpgradeStart);
  hdr.seqno = htole16(seqno);
	
  if (debug) {
    print_pkt(__FUNCTION__, "", (unsigned char *)&hdr, sizeof(hdr));
  }

  return send(s, &hdr, sizeof(hdr), 0) < 0;
}

static int SendUpgrade(int s, const unsigned char *mac,
		       unsigned short seqno, unsigned int addr,
		       void *data, unsigned int dlen, Cmd_e cmd)
{
  struct hdr_s hdr;
  unsigned char buf[HDR_SIZE+MAX_PAYLOAD_LEN];
  unsigned int len;

  if (cmd != UpgradeData && cmd != UpgradeVerify)
    return -1;

  memset(buf, 0, sizeof(buf));
  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.da, mac, ETH_ALEN);
  memcpy(hdr.sa, own_mac, ETH_ALEN);
  hdr.eth_type = htons(ETH_P_SERCOMM);
  hdr.cmd = htole16(cmd);
  hdr.seqno = htole16(seqno);
  hdr.byte_off = htole16(addr & 0xf);
  hdr.chunk_off = htole16(addr >> 4);

  len = MIN(MAX_PAYLOAD_LEN, dlen);
  hdr.length = htole16(len);

  memcpy(buf, &hdr, sizeof(hdr));
  memcpy(buf+sizeof(hdr), data, len);

  if (debug) {
    print_pkt(__FUNCTION__, cmd == UpgradeData ? "Write" : "Verify", buf,
	      sizeof(hdr)+len);
  }

  return send(s, buf, sizeof(hdr)+len, 0) < 0;
}

/* max. number of boards we are able to detect */
#define MAX_NR_BOARDS 16

static struct hw_info_s {
  unsigned char mac[ETH_ALEN];
  struct pid_s pid;
} hwinfo[MAX_NR_BOARDS];

/* dump the content of a hwinfo */
void DumpHWInfo(struct hw_info_s *s, int nr)
{
  printf("%u: %02x:%02x:%02x:%02x:%02x:%02x  %s func %u company %c%c "
	 "version %u.%u-%u\n",
	 nr, s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], 
	 s->mac[5], s->pid.hw_id, s->pid.function,
	 s->pid.company[0], s->pid.company[1],
	 s->pid.version[0]>>4, s->pid.version[0]&0xf, s->pid.version[1]);
}

static int alarm_raised;

/* my handler for SIGALRM */
static void alarm_handler(int dummy)
{
  alarm_raised=1;
}

/* wait for a response from the given mac address and with a given seqno.
   time is in seconds.
   return >= 0 if we got one (the return value is the error code from the
   response or -1 for timeout or read error. */
int ReadResp(int s, unsigned char *mac, unsigned int seqno, unsigned int time)
{
  fd_set r,e;
  struct sockaddr_ll from;
  socklen_t fl;
  unsigned char ibuf[1536];
  sighandler_t old_handler;
  int rc=0;

  old_handler=signal(SIGALRM, alarm_handler);
  alarm_raised=0;
  alarm(time);
  while (1) {

    /* create the fd sets */
    FD_ZERO(&r);
    FD_SET(s, &r);
    e=r;

    rc=select(s+1, &r, NULL, &e, NULL);

    if (rc < 0) {

      if (errno == EINTR) {
	if (!alarm_raised) {
	  continue;
	} else {
	  err("timeout during select");
	  goto end;
	}
      }
      err("select failed (%m)");
      goto end;
    }

    if (FD_ISSET(s,&e)) {
      err("error cond. on socket");
      rc=-1;
      goto end;
    }

    if (FD_ISSET(s,&r)) {
      fl = sizeof(from);
      rc = recvfrom(s,ibuf,sizeof(ibuf), 0,
		    (struct sockaddr *)&from, &fl);
      if (rc < 0) {
	err("recvfrom failed (%m)");
	goto end;
      }

      /* should be an incoming packet */
      if (from.sll_pkttype != PACKET_OUTGOING) {
	struct hdr_s hdr;

	memcpy(&hdr, ibuf, sizeof(hdr));

	if (hdr.eth_type != htons(ETH_P_SERCOMM) || 
	    memcmp(hdr.sa, mac, ETH_ALEN))
	  /* either wrong ethtype or 
	     wrong source mac address */
	  continue;
				 
	if (debug) {
	  /* dump received data */
	  print_pkt(__FUNCTION__, "", ibuf, rc);
	}

	if (le16toh(hdr.seqno) == seqno) {
	  rc = ibuf[sizeof(struct hdr_s)] | 
	    (ibuf[sizeof(struct hdr_s)+1]<<8);
	  goto end;
	}

	err("%s: expected seq no %x, got %x",
	    __FUNCTION__, seqno, le16toh(hdr.seqno));
	continue;
      } /* if (from.sll_pkttype != PACKET_OUTGOING) */
    }
  } /* while (1) */
 end:
  alarm(0); /* delete any alarm still running */
  signal(SIGALRM, old_handler); /* restore old handler */
  return rc;
} /* ReadResp */

/* read all hw info responses in a certain time on socket s.
   return the number of responses or < 0 for error */
int ReadHWInfoResp(int s)
{
  int nr = 0;
  sighandler_t old_handler;
  unsigned int time=2;
  int rc = -1;

  old_handler=signal(SIGALRM, alarm_handler);
  alarm_raised=0;
  alarm(time);

  /* read responses with timeout of 2 seconds */
  while (1) {
    fd_set r,e;
    struct sockaddr_ll from;
    socklen_t fl;
    unsigned char ibuf[1536];

    /* create the fd sets */
    FD_ZERO(&r);
    FD_SET(s, &r);
    e=r;

    rc=select(s+1, &r, NULL, &e, NULL);
    if (rc < 0) {
      if (errno == EINTR) {
	if (alarm_raised)
	  break;
	else
	  continue;
      }
      err("select failed (%m)");
      goto end;
    }

    if (FD_ISSET(s,&e)) {
      err("error cond. on socket");
      rc = -1; goto end;
    }

    if (FD_ISSET(s,&r)) {
      fl = sizeof(from);
      rc = recvfrom(s,ibuf,sizeof(ibuf), 0, (struct sockaddr *)&from, &fl);
      if (rc < 0) {
	err("recvfrom failed (%m)");
	goto end;
      }
      if (from.sll_pkttype != PACKET_OUTGOING) {
	/* should be an incoming packet */
	if (ibuf[2*ETH_ALEN] == 0x88 && ibuf[2*ETH_ALEN+1] == 0x88) {
	  memcpy(hwinfo[nr].mac, ibuf+ETH_ALEN, ETH_ALEN);
	  memcpy(hwinfo[nr].pid.reserved,
		 ibuf+sizeof(struct hdr_s),
		 sizeof(hwinfo[nr].pid) - 
		 offsetof(struct pid_s, reserved));
	  nr++;
	  if (debug) {
	    print_pkt(__FUNCTION__, "", ibuf, rc);
	  }
	}
      }
    }
  } /* while (1); */

  /* we arrive here if the alarm just let us break from the while (1) loop */
  rc=nr;
 end:
  alarm(0); /* delete any alarm still running */
  signal(SIGALRM, old_handler);
  return rc;
}

int UpdateFW(int s, const char *fw_name, struct hw_info_s *hw)
{
  int fd = -1;
  unsigned char *mm;
  unsigned char *fw = NULL;
  unsigned char *cptr;
  unsigned char *sec_pid;
  unsigned int off;
  unsigned int seqno;
  struct stat st;
  int rc = -1;
  struct pid_s pid;

#define SHOW_PROGRESS(c) do { putchar(c); fflush(stdout); } while (0)

  /* open and map firmware file */
  if ((fd=open(fw_name, O_RDONLY)) < 0) {
    err("failed to open firmware file %s (%m)", fw_name);
    goto end;
  }

  if (fstat(fd, &st) < 0) {
    err("fstat failed on %s (%m)", fw_name);
    goto end;
  }

  if (!S_ISREG(st.st_mode)) {
    err("%s is no regular file", fw_name);
    goto end;
  }

  if (st.st_size > MAX_FW_SIZE) {
    err("%s is too large (0x%lx > 0x%lx)", fw_name,
	(unsigned long int)st.st_size, MAX_FW_SIZE);
    goto end;
  }

  if (st.st_size < MIN_PID2_OFFSET) {
    err("firmware file too small (must be >= 0x%x)", MIN_PID2_OFFSET);
    goto end;
  }

  if ((mm=(unsigned char *)mmap(NULL, MAX_FW_SIZE, PROT_READ,
				MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    err("failed to mmap firmware file (%m)");
    goto end;
  }

  if (!(fw=malloc(st.st_size))) {
    err("failed to malloc %lx byte", st.st_size);
    munmap(mm, MAX_FW_SIZE);
    goto end;
  }

  memcpy(fw,mm,st.st_size);
  munmap(mm, MAX_FW_SIZE);

#if 0 /* openwrt images currently contain no real cfe, only zeros */
  /* check that the firmware starts with the boot loader */
  if (memcmp(fw+CFE_MAGIC_OFFSET, "CFE1CFE1", 8)) {
    err("invalid firmware file %s - no CFE1CFE1 at offset 0x%x. "
	"Bootloader missing?", fw_name, CFE_MAGIC_OFFSET);
    goto end;
  }
#endif

  /* check that we have a pid area at offset 0xff80 */
  memcpy(&pid, fw+PID_OFFSET, sizeof(pid));

  if (memcmp(pid.magic, PID_MAGIC, PID_MAGIC_LEN) ||
      memcmp(pid.magic2, PID_MAGIC, PID_MAGIC_LEN)) {
    err("invalid firmware file %s - cannot find pid at offset 0x%x.",
	fw_name, PID_OFFSET);
    goto end;
  }

  /* check that the firmware contains the correct hw id (in the pid) */
  if (strncmp(hw->pid.hw_id, pid.hw_id, sizeof(pid.hw_id))) {
    err("invalid firmware file %s - bad hardware id: expected %s, found %s",
	fw_name, hw->pid.hw_id, pid.hw_id);
    goto end;
  }

  /* check that we have a pid or pid2 area at offset >= 0x200000.
     If not, then fail.
     If we found a pid area, convert it to a pid2.
  */
	
  for(cptr=fw+MIN_PID2_OFFSET,sec_pid=NULL;
      cptr < (fw + st.st_size-PID_MAGIC_LEN); cptr++) {
    if (!memcmp(cptr, PID2_MAGIC, PID_MAGIC_LEN))
      break;
    if (cptr < (fw + st.st_size - sizeof(struct pid_s)) &&
	!memcmp(cptr, PID_MAGIC, PID_MAGIC_LEN) &&
	!memcmp(cptr+offsetof(struct pid_s,magic2), 
		PID_MAGIC, PID_MAGIC_LEN)) {
      sec_pid=cptr;
    }
  }
  if (cptr >= (fw + st.st_size-PID_MAGIC_LEN)) {
    dbg("no pid2 found");
    if (sec_pid != NULL) {
      printf("#INFO converting pid area at offset 0x%lx into a pid2\n",
	     sec_pid-fw);
      memcpy(sec_pid, PID2_MAGIC, PID_MAGIC_LEN);
      memcpy(sec_pid+offsetof(struct pid_s,magic2),
	     PID2_MAGIC, PID_MAGIC_LEN);
    } else
      /* fail if we found neither pid nor pid2 area
	 at an offset >=0x20000 */
      goto end;
  }

  /* start updating the firmware */
  seqno=0;
  if (SendUpgradeStart(s, hw->mac, seqno)) {
    err("failed to send UPGRADE START");
    goto end;
  }

  /* wait for response */
  if ((rc=ReadResp(s, hw->mac, seqno, 2000))) {
    err("ReadResp after upgrade start failed with %d", rc);
    goto end;
  }

  SHOW_PROGRESS('S');

  seqno++;
  off=0;
  while (off < st.st_size) {
    unsigned int nr = MIN(MAX_PAYLOAD_LEN,st.st_size-off);

    /* send update data */
    if ((rc=SendUpgrade(s, hw->mac, seqno, off, fw+off, nr,
			UpgradeData)) < 0)
      goto end;

    /* wait for response */
    if ((rc=ReadResp(s, hw->mac, seqno, 2000))) {
      err("ReadResp after upgrade start failed with %d", rc);
      goto end;
    }

    SHOW_PROGRESS('F');

    off += nr;
    seqno++;
  } /* while (off < st.st_size) */

  /* verify the update */
  off=0;
  while (off < st.st_size) {
    unsigned int nr = MIN(MAX_PAYLOAD_LEN,st.st_size-off);

    /* send update data */
    if ((rc=SendUpgrade(s, hw->mac, seqno, off, fw+off, nr, UpgradeVerify)) < 0)
      goto end;

    /* wait for response */
    if ((rc=ReadResp(s, hw->mac, seqno, 2000))) {
      err("ReadResp after upgrade start failed with %d", rc);
      goto end;
    }

    SHOW_PROGRESS('V');

    off += nr;
    seqno++;
  } /* while (off < st.st_size) */


  /* send a Reset to the target */
  if (SendReboot(s, hw->mac)) {
    err("failed to reboot (%m)");
    rc=-1;
  }

 end:
  if (fw)
    free(fw);
  if (fd >= 0)
    close(fd);
  return rc;
}


static const unsigned char bc_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

int main(int argc, char **argv)
{
  char *devname;
  int s;
  int idx;
  struct ifreq ifr;
  struct sockaddr_ll sa;
  int nr;
  int i;
  unsigned int board_nr;
  int devname_idx=1;

  if (argc > 1 && argv[1][0] == '-') {
    if (argv[1][1] == 'v') {
      debug=1;
      devname_idx++;
    } else {
      if (argv[1][1] == 'h') {
	usage(argv[0]);
	return 0;
      }
    }
  }

  if (argc < devname_idx+1) {
    err("ethernet device missing");
    usage(argv[0]);
    return 1;
  }

  devname = argv[devname_idx];

  /* we set the protocol the one used for sercomm to
     filter the other packets out */
  s=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0) {
    err("failed to create raw socket (%m)");
    return 2;
  }

  /* get the interface index*/
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ-1] = '\0';

  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
    err("failed to find network interface %s", devname);
    return 3;
  }

  idx = ifr.ifr_ifindex;

  /* check whether the interface is up or down */
  if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
    err("failed to check up/down (%m)");
    return 4;
  }
  if ((ifr.ifr_flags & IFF_UP) == 0) {
    err("network interface %s is down", devname);
    return 4;
  }
		
  /* obtain own MAC address */
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    err("failed to get the own MAC address");
    return 5;
  }
  memcpy(own_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = idx;
  sa.sll_protocol = htons(ETH_P_ALL);

  /* try to bind the raw socket to the interface */
  if (bind(s,(struct sockaddr*)&sa,(socklen_t)sizeof(sa))) {
    err("failed to bind the raw socket to %s (%m)", devname);
    return 6;
  }

  /* send a hw info request to the broadcast mac */
  if (SendHWInfoReq(s,bc_mac) < 0) {
    err("failed to send HW Info Req (%m)");
    return 7;
  }

  nr = ReadHWInfoResp(s);

  if (nr < 0)
    return 8;
  if (!nr) {
    printf("no boards found\n");
    return 0;
  }

  for(i=0; i < nr; i++) {
    DumpHWInfo(&hwinfo[i],i);
  }

  if (argc > devname_idx+1) {
    /* a file to flash was given */
    if (nr > 1) {
      do {
	printf("choose a board number(0-%d): ", nr-1);
	scanf("%u\n", &board_nr);
      } while (board_nr >= nr);
    } else
      board_nr=0;
	
    return UpdateFW(s, argv[devname_idx+1], &hwinfo[board_nr]);
  } else
    return 0;
}
