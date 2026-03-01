/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026

    Implemented By:    Shea Parcell and Adam Bergen
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double      baseTime ;  // capturing time (in seconds ) of the very 1st packet in this file
bool        baseTimeSet = false ;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname'
    and read its global header into buffer 'p'
    Side effects:
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
	// Always check for incoming NULL poiters
    if(fname == NULL || p == NULL) {
        return -1;
    }
	// Successfully open the input 'fname'
    pcapInput = fopen(fname, "rb");
    if(pcapInput == NULL) {
        return -1;
    }
    //read input into the golbal header
    if(fread(p, sizeof(pcap_hdr_t), 1, pcapInput) != 1) {
        return -1;
    }

    bytesOK = true;
    microSec = true;

    if (p->magic_number == 0xd4c3b2a1){
        bytesOK = false;
    }
    else if (p->magic_number == 0x4d3cb2a1)
    {
        bytesOK = false;
        microSec = false;
    }
    else if (p->magic_number == 0xa1b23c4d){
        microSec = false;
    }

    if (!bytesOK)
    {
        p->version_major = htons(p->version_major);
        p->version_minor = htons(p->version_minor);
        p->thiszone = htonl(p->thiszone);
        p->sigfigs = htonl(p->sigfigs);
        p->snaplen = htonl(p->snaplen);
        p->network = htonl(p->network);
    }
    // Determine the capturer's byte ordering
    // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.

}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p )
{
    printf("magic number %X\n", p->magic_number );
    printf("major version %d\n", p->version_major);
    printf("minor version %d\n", p->version_minor);
    printf("GMT to local correction %d seconds\n", p->thiszone);
    printf("accuracy of timestamps %d\n", p->sigfigs);
    printf("Cut-off max length of captured packets %d\n", p->snaplen);
    printf("data link type %d\n", p->network);
    // Missing Code Here
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame)
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload

    If this is the very first packet from the PCAP file, set the baseTime

    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    // Check for incoming NULL pointers
    if (!p || !ethFrame){
        return false;
    }
    // Read the header of the next paket in the PCAP file
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1){
        return false;
    }
    // Did the capturer use a different
    // byte-ordering than mine (as determined by the magic number)?
    if( ! bytesOK )
    {
        p->ts_sec = htonl(p->ts_sec);
        p->ts_usec = htonl(p->ts_usec);
        p->incl_len = htonl(p->incl_len);
        p->orig_len = htonl(p->orig_len);
        // reorder the bytes of the fields in this packet header
    }

    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    if (fread(ethFrame, p->incl_len, 1, pcapInput) != 1){
        return false;
    }

    // If necessary, set the baseTime .. Pay attention to possibility of nano second
    // time precision (instead of micro seconds )

    double pktTime = p->ts_sec;
    if (microSec){
        pktTime += p->ts_usec / 1e6;
    }
    else{
        pktTime += p->ts_usec / 1e9;
    }

    if (!baseTimeSet)
    {
        baseTime = pktTime;
        baseTimeSet = true;
    }

    return true ;
}


/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
static int pktnum = 1;
void printPacketMetaData( const packetHdr_t *p  )
{
        // Missing Code Here
    double pktTime = p->ts_sec;

    if (microSec){
        pktTime += p->ts_usec / 1e6;
    }
    else{
        pktTime += p->ts_usec / 1e9;
    }

    printf("%6.0d %14.6f %6u / %6u ", pktnum++, pktTime - baseTime, p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */

void printPacket( const etherHdr_t *frPtr )
{
    // Missing Code Here
    // print Source/Destination MAC addresses
    char src[20], dst[20];
    uint16_t eth_type = ntohs(frPtr->eth_type);
    if (eth_type == PROTO_ARP)
    {
        macToStr(frPtr->eth_srcMAC, src);
        macToStr(frPtr->eth_dstMAC, dst);
        printf("%-20s %-20s %-8s ", src, dst, "ARP");

        arpMsg_t *arp = (arpMsg_t *)((uint8_t *)frPtr + ETHERNETHLEN);
        printARPinfo(arp);
    }
    else if (eth_type == PROTO_IPv4)
    {
        ipv4Hdr_t *ip = (ipv4Hdr_t *)((uint8_t *)frPtr + ETHERNETHLEN * 2 + 2); 
        ipToStr(ip->ip_srcIP, src);
        ipToStr(ip->ip_dstIP, dst);

        char *protoStr = "IP";
        if (ip->ip_proto == PROTO_ICMP)
        {
            protoStr = "ICMP";
        }
        else if (ip->ip_proto == PROTO_TCP)
        {
            protoStr = "TCP";
        }
        else if (ip->ip_proto == PROTO_UDP)
        {
            protoStr = "UDP";
        }
        printf("%-20s %-20s %-8s ", src, dst, protoStr);

        printIPinfo(ip);
        if (ip->ip_proto == PROTO_ICMP)
        {
            uint8_t ihl = ip->ip_verHlen & 0x0f;
            icmpHdr_t *icmp = (icmpHdr_t *)((uint8_t *)ip +(ihl * 4));
            printICMPinfo(icmp);

            uint16_t totalLen = ntohs(ip->ip_totLen);
            unsigned appDataLen = totalLen - (ihl * 4) - 8;
            printf(" AppData=%5u", appDataLen);
        }
    }

}

/*

PROJECT 1 METHODS

*/

void printARPinfo( const arpMsg_t  *arp) 
{
    uint16_t op = ntohs(arp->arp_oper);

    char sip[20], tip[20], smac[20];
    ipToStr(arp->arp_spa, sip);
    ipToStr(arp->arp_tpa, tip);
    macToStr(arp->arp_tha, smac);

    if (op == 1)   // request
        printf("Who has %s ? Tell %s", tip, sip);
    else if (op == 2)   // reply
        printf("%s is at %s", sip, smac);
}


void      printIPinfo ( const ipv4Hdr_t * ) ;
unsigned  printICMPinfo( const icmpHdr_t * ) ;



/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}

char *ipToStr( const IPv4addr ip , char *ipStr )
{
    sprintf(ipStr, "%u.%u.%u.%u", ip.byte[0], ip.byte[1], ip.byte[2], ip.byte[3]);
    return ipStr;
}
