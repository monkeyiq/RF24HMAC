
#include <RF24HMAC.h>
#include <SPI.h>
#include <sha256.h>


const int packetlen = 32;
const int maclen = 32;


RF24HMAC::RF24HMAC( RF24& m_delegate, const char* mackey ) 
    : m_delegate( m_delegate )
    , bufidx(0)
{
    Sha256.initHmac( (const uint8_t*)mackey, strlen( mackey ));
    memset( buf, 0, bufsz );
}

bool RF24HMAC::waitForPacket( uint16_t timeoutMS )
{
    // Wait here until we get a response, or timeout
    unsigned long started_waiting_at = millis();
    bool timeout = false;
    while ( ! m_delegate.available() && ! timeout )
        if (millis() - started_waiting_at > timeoutMS )
            timeout = true;
    return timeout;
}
    

///////
// writing

void RF24HMAC::beginWritingPacket()
{
    bufidx = 0;
    memset( buf, 0, bufsz );
}


bool RF24HMAC::write( const uint8_t* data, uint8_t len )
{
    for( int i=0; i< len; i++ )
        buf[bufidx++] = data[i];
    return 1;
}

void RF24HMAC::writeu32( uint32_t v )
{
//  printf("writeu32 bufidx:%d v:%ld\n", bufidx, v );
    buf[bufidx++] = (v >> 24) & 0xFF;
    buf[bufidx++] = (v >> 16) & 0xFF;
    buf[bufidx++] = (v >>  8) & 0xFF;
    buf[bufidx++] = (v >>  0) & 0xFF;
}

void RF24HMAC::writeu16( uint16_t v )
{
//  printf("writeu32 bufidx:%d v:%ld\n", bufidx, v );
    buf[bufidx++] = (v >>  8) & 0xFF;
    buf[bufidx++] = (v >>  0) & 0xFF;
}

bool RF24HMAC::done()
{
    printHash( "raw first data:", buf );
        
    bool ret = m_delegate.write( (const uint8_t*)buf, packetlen );
    printf("original send ret:%d\n\r", ret );
        
    if( !ret )
        return ret;
        
    Sha256.write( (const uint8_t*)buf, packetlen );
    uint8_t* mac = Sha256.resultHmac();
    printHash( "mac:", mac );

    // maybe to get ack back?
    // seems that way.
    m_delegate.startListening();
    delay(1);
    m_delegate.stopListening();
        

    ret = m_delegate.write( mac, maclen );
    printf("mac send ret:%d\n\r", ret );
    return ret;
}

///////
// reading a packet
//
void RF24HMAC::remember( uint8_t* data, int datalen )
{
    bufidx = datalen;
    memcpy( buf, data, datalen );
}
bool RF24HMAC::isValidHMac( uint8_t* wiremac, int wiremaclen )
{
    Sha256.write( (const uint8_t*)buf, packetlen );
    uint8_t* mac = Sha256.resultHmac();
    printHash( "mac:", mac );
    
    return !memcmp( mac, wiremac, wiremaclen );
}

uint8_t* RF24HMAC::readAuthenticatedPacket()
{
    int ret = 0; // fail by default
    // Dump the payloads until we've gotten everything
    bool done = false;
    int haveDataPacket = 0;
      
    while (!done)
    {
        uint8_t data[33];
        memset(data,0,32);
        done = m_delegate.read( data, 32 );
        printf("read a packet done:%d haveDataPacket:%d\n\r", done, haveDataPacket );
        haveDataPacket++;
        
        if( haveDataPacket == 1 )
        {
            remember( data, 32 );
            
            // wait for hmac packet.
            done = 0;
            int timedOut = waitForPacket();
            printf("****** timedOut:%d have more packets:%d\n\r", timedOut, m_delegate.available() );

            printHash( "raw first data:", data );
            
        }
        if( haveDataPacket == 2 )
        {
            printHash( "mac:", data );

            int isValid = isValidHMac( data, maclen );
            printf("mac isValid:%d\n\r", isValid );
            ret = isValid;
        }
        
        // Delay just a little bit to let the other unit
        // make the transition to receiver
        delay(20);
    }

    if( !ret )
    {
        // if we failed, then don't even let the caller see the bad data
        memset( buf, 0, bufsz );
        return 0;
    }
        
    return buf;
}


uint32_t
RF24HMAC::readu32( uint8_t* buf, int& bufidx )
{
  uint32_t ret = 0;
  ret |= (uint32_t)buf[bufidx++] << 24;
  ret |= (uint32_t)buf[bufidx++] << 16;
  ret |= (uint32_t)buf[bufidx++] <<  8;
  ret |= buf[bufidx++] <<  0;
  return ret;
}

void
RF24HMAC::printHash( const char* msg, uint8_t* hash )
{
    Serial.print( msg );
    int i;
    for (i=0; i<32; i++) {
        Serial.print("0123456789abcdef"[hash[i]>>4]);
        Serial.print("0123456789abcdef"[hash[i]&0xf]);
    }
    Serial.println();
}
