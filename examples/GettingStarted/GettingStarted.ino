
#include <SPI.h>
#include "RF24.h"
#include "RF24HMAC.h"
#include "printf.h"
#include <sha256.h>

RF24 radio(9,10);

// Radio pipe addresses for the 2 nodes to communicate.
const uint64_t pipes[2] = { 0xF0F0F0F0E1LL, 0xF0F0F0F0D2LL };

// The various roles supported by this sketch
typedef enum { role_ping_out = 1, role_pong_back } role_e;

// The debug-friendly names of those roles
const char* role_friendly_name[] = { "invalid", "Ping out", "Pong back"};

// The role of the current running sketch
role_e role = role_pong_back;

void setup(void)
{
  Serial.begin(57600);
  printf_begin();
  printf("\n\rRF24/examples/GettingStarted/\n\r");
  printf("ROLE: %s\n\r",role_friendly_name[role]);
  printf("*** PRESS 'T' to begin transmitting to the other node\n\r");

  radio.begin();
  radio.setRetries(15,15);
  radio.setPayloadSize( 32 );

  radio.openReadingPipe(1,pipes[1]);
  radio.startListening();
  radio.printDetails();
}



void loop(void)
{
  if (role == role_ping_out)
  {
    radio.stopListening();

    // Take the time, and send it.  This will block until complete
    uint32_t time = millis();
    printf("\n\nNow sending %lu...\n",time);

    // Write packet with HMAC
    RF24HMAC radiomac( radio, "wonderful key" );
    radiomac.beginWritingPacket();
    radiomac.writeu32( time );
    bool ok = radiomac.done();
    printf("wrote HMAC packet, return value: %s\n\r", ok ? "ok." : "failed." );


    radio.startListening();
    byte timeout = radiomac.waitForPacket();
    
    if ( timeout )
    {
        printf("Failed, response timed out.\n\r");
    }
    else
    {
        unsigned long got_time;
        radio.read( &got_time, sizeof(unsigned long) );
        printf("Got response %lu, round-trip delay: %lu\n\r",got_time,millis()-got_time);
    }
    
    delay(1000);
  }

  //
  // Pong back role.  Receive each packet, dump it out, and send it back
  //
  if ( role == role_pong_back )
  {
      unsigned long got_time = 0;

      if ( radio.available() )
      {
          // Check incoming packet, it should have a valid HMAC
          RF24HMAC radiomac( radio, "wonderful key" );
          uint8_t* packetData = 0;
          if( packetData = radiomac.readAuthenticatedPacket() )
          {
              int di = 0;
              uint32_t v = radiomac.readu32( packetData, di );
              got_time = v;
              printf("Got payload %lu...\n\r",got_time);
          }
      
          radio.stopListening();
          radio.write( &got_time, sizeof(unsigned long) );
          printf("Sent response.\n\r\n\r\n\r");
          radio.startListening();
      }
  }

  
  //
  // Change roles
  //
  if ( Serial.available() )
  {
    char c = toupper(Serial.read());
    if ( c == 'T' && role == role_pong_back )
    {
      printf("*** CHANGING TO TRANSMIT ROLE -- PRESS 'R' TO SWITCH BACK\n\r");

      // Become the primary transmitter (ping out)
      role = role_ping_out;
      radio.openWritingPipe(pipes[0]);
      radio.openReadingPipe(1,pipes[1]);
    }
    else if ( c == 'R' && role == role_ping_out )
    {
      printf("*** CHANGING TO RECEIVE ROLE -- PRESS 'T' TO SWITCH BACK\n\r");
      
      // Become the primary receiver (pong back)
      role = role_pong_back;
      radio.openWritingPipe(pipes[1]);
      radio.openReadingPipe(1,pipes[0]);
    }
  }
}


