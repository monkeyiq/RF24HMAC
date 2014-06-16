/*
 
 Copyright (C) 2014 Ben Martin

 This is a wrapper on RF24 which provides HMAC authenticated packet
 communication. This is a free time hobby, the code is a little rough
 around the edges, (good, or well, ok) pull requests accepted :)

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 version 3 as published by the Free Software Foundation.
 */

#include "nRF24L01.h"
#include "RF24.h"


class RF24HMAC 
{
    RF24& m_delegate;
    enum 
    {
        bufsz = 64
    };
    uint8_t bufidx;
    uint8_t buf[ bufsz ];

  public:
    
    RF24HMAC( RF24& m_delegate, const char* mackey );

    ///////
    // utils
    
    // return 1 if timed out waiting
    bool waitForPacket( uint16_t timeoutMS = 500 );
    void printHash( const char* msg, uint8_t* hash );

    
    ///////
    // writing

    // called to start a packet to reset indexes for writeu32() etc
    void beginWritingPacket();
    
    bool write( const uint8_t* data, uint8_t len );
    void writeu32( uint32_t v );
    void writeu16( uint16_t v );

    /**
     * Send the payload that was built up with write() calls and also the
     * HMAC packet.
     */
    bool done();

    
    ///////
    // reading a packet
    //

    /**
     * Gets a 32 byte packet that has a valid HMAC or null of there
     * is no packet or the HMAC failed to match.
     */
    uint8_t* readAuthenticatedPacket();

    uint32_t readu32( uint8_t* buf, int& bufidx );

  protected:
    void remember( uint8_t* data, int datalen );
    bool isValidHMac( uint8_t* wiremac, int wiremaclen );
};
