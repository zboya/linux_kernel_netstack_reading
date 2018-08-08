#include<stdio.h>

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)


#define USEC_PER_SEC	1000000L
#define USEC_PER_MSEC	1000L


static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;


static long bbr_rate_bytes_per_sec(long rate, long gain)
{
	// tcp_mss_to_mtu 拿到mtu
	// rate = bw * mtu * gain * 1<<8 * 1000000L / 1<<24
	rate *= 1500;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

int main() {
    long bw;
    long rtt_us;
    long rate;
    bw = 10 * BW_UNIT;
    rtt_us = USEC_PER_MSEC;	
	bw = bw /rtt_us;
    printf("bw: %lld\n",bw);
    rate = bbr_rate_bytes_per_sec(bw,bbr_high_gain);
    printf("rate: %lld\n",rate);
    return 0;
}