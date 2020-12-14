import React, { useState } from 'react';
import { CircularProgress, Grid, TextareaAutosize, TextField } from '@material-ui/core';
import Packet from './Packet';

import Websocket from 'react-websocket';

const Packets = () => {

  const [packetIndex, setPacketIndex] = useState(0);
  const [packetsList, setPacketsList] = useState([]);

  return (
    <>
      <Websocket
        url='ws://localhost:9002'
        onMessage={(message) => {
          const parsedMessage = JSON.parse(message);
          packetsList.push(parsedMessage.package);
          setPacketsList([...packetsList]);
        }}
      />
      {
        packetsList.length ?
        <Packet packet={packetsList[packetIndex]} />
        : null
      }
      <br />
      <Grid container>
        { 
          packetsList.length === 0 &&
          <Grid 
            item 
            xs={12}
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}
          >
            <CircularProgress size={25} style={{ color: 'black' }}/>
          </Grid>
        }
        <Grid item style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center'
        }}>
          <TextField
            label='Packet Index'
            type='number'
            placeholder='Packet Index'
            style={{
              marginLeft: 100,
            }}
            onChange={(event) => {
                if ((Number(event.target.value) && packetsList.length > Number(event.target.value)) || (Number(event.target.value) === 0)) {
                  setPacketIndex(Number(event.target.value))
                }
              }
            }
          />
          <span style={{ marginTop: 20 }}>/ {packetsList.length-1} </span>
        </Grid>
        <Grid item>
          <TextareaAutosize 
            value={packetsList.map((packet) => JSON.stringify(packet, null, 2))}
            rowsMin={3}
            rowsMax={12}
            style={{
              width: 400,
              marginLeft: 100,
            }}
          />
        </Grid>
      </Grid>
    </>
  );

};

export default Packets;