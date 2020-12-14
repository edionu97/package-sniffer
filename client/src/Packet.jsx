import React, { useState } from 'react';

import PropTypes from 'prop-types';
import { Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogTitle, Grid, makeStyles } from '@material-ui/core';
import { Check, Clear, Sms} from '@material-ui/icons';

const protocols = {
  0: 'HOPOPT',
  1: 'ICMP',
  2: 'IGMP',
  3: 'GGP',
  4: 'IPv4',
  5: 'ST',
  6: 'TCP',
  7: 'CBT',
  8: 'EGP',
  9: 'IGP',
  10: 'BBN-RCC-MON',
  11: 'NVP-II',
  12: 'PUP',
  13: 'ARGUS',
  14: 'EMCON',
  15: 'XNET',
  16: 'CHAOS',
  17: 'UDP',
  18: 'MUX',
  19: 'DCN-MEAS',
  20: 'HMP',
  21: 'PRM',
  22: 'XNS-IDP',
  23: 'TRUNK-1',
  24: 'TRUNK-2',
  25: 'LEAF-1',
  26: 'LEAF-2',
  27: 'RDP',
  28: 'IRTP',
  29: 'ISO-TP4',
  30: 'NETBLT',
  31: 'MFE-NSP',
  32: 'MERIT-INP',
  33: 'DCCP',
  34: '3PC',
  35: 'IDPR',
  36: 'XTP',
  37: 'DDP',
  38: 'IDPR-CMTP',
  39: 'TP++',
  40: 'IL',
  41: 'IPv6',
  42: 'SDRP',
  43: 'IPv6-Route',
  44: 'IPv6-Frag',
  45: 'IDRP',
  46: 'RSVP',
  47: 'GRE',
  48: 'DSR',
  49: 'BNA',
  50: 'ESP',
  51: 'AH',
  52: 'I-NLSP',
  53: 'SWIPE',
  54: 'NARP',
  55: 'MOBILE',
  56: 'TLSP',
  57: 'SKIP',
  58: 'IPv6-ICMP',
  59: 'IPv6-NoNxt',
  60: 'IPv6-Opts',
  62: 'CFTP',
  64: 'SAT-EXPAK',
  65: 'KRYPTOLAN',
  66: 'RVD',
  67: 'IPPC',
  69: 'SAT-MON',
  70: 'VISA',
  71: 'IPCV',
  72: 'CPNX',
  73: 'CPHB',
  74: 'WSN',
  75: 'PVP',
  76: 'BR-SAT-MON',
  77: 'SUN-ND',
  78: 'WB-MON',
  79: 'WB-EXPAK',
  80: 'ISO-IP',
  81: 'VMTP',
  82: 'SECURE-VMTP',
  83: 'VINES',
  84: 'TTP/IPTM',
  85: 'NSFNET-IGP',
  86: 'DGP',
  87: 'TCF',
  88: 'EIGRP',
  89: 'OSPFIGP',
  90: 'Sprite-RPC',
  91: 'LARP',
  92: 'MTP',
  93: 'AX.25',
  94: 'IPIP',
  95: 'MICP',
  96: 'SCC-SP',
  97: 'ETHERIP',
  98: 'ENCAP',
  100: 'GMTP',
  101: 'IFMP',
  102: 'PNNI',
  103: 'PIM',
  104: 'ARIS',
  105: 'SCPS',
  106: 'QNX',
  107: 'A/N',
  108: 'IPComp',
  109: 'SNP',
  110: 'Compaq-Peer',
  111: 'IPX-in-IP',
  112: 'VRRP',
  113: 'PGM',
  115: 'L2TP',
  116: 'DDX',
  117: 'IATP',
  118: 'STP',
  119: 'SRP',
  120: 'UTI',
  121: 'SMP',
  122: 'SM',
  123: 'PTP',
  124: 'ISIS',
  125: 'FIRE',
  126: 'CRTP',
  127: 'CRUDP',
  128: 'SSCOPMCE',
  129: 'IPLT',
  130: 'SPS',
  131: 'PIPE',
  132: 'SCTP',
  133: 'FC',
  134: 'RSVP-E2E-IGNORE',
  135: 'Mobility Header',
  136: 'UDPLite',
  137: 'MPLS-in-IP',
  138: 'manet',
  139: 'HIP',
  140: 'Shim6',
  141: 'WESP',
  142: 'ROHC',
  143: 'Ethernet',
};

const useStyles = makeStyles({
  centeredLeft: {
    display: 'flex',
    justifyContent: 'left',
    alignItems: 'center',
    fontSize: 14,
  },
  centered: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
  },
  centeredTitle: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 20,
    fontSize: 20,
    fontFamiliy: 'Arial',
  },
  card: {
    backgroundColor: '#cfff95'
  }
});

const TCPHeaderFlag = ({
  flagText,
  checked,
}) => {

  return (
    <>
      {flagText}: { checked ? <Check style={{color: 'green'}} /> : <Clear style={{color: 'red'}} />}
    </>
  );
};

TCPHeaderFlag.propTypes = {
  flagText: PropTypes.string.isRequired,
  checked: PropTypes.number.isRequired,
};

const PayloadModal = ({
  children,
  closeModal,
  open,
}) => {

  return (
    <Dialog open={open}>
      <DialogTitle>
        Payload
      </DialogTitle>
      <DialogContent>
        {children}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => closeModal()} fullWidth>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );

};

const Packet = ({
  packet,
}) => {

  const classes = useStyles();

  const [openModalPayload, setOpenModalpayload] = useState(false);

  const {
      acknowledge_flag,
      acknowledge_number,
      checksum,
      destination_port,
      finish_flag,
      header_length,
      ip_header: {
        checksum: ipChecksum,
        destination_ip,
        eth_header: {
          destination_mac_address,
          protocol: ethProtocol,
          source_mac_address,
        },
        identification,
        ip_header_length,
        ip_version,
        protocol,
        size_of_packet,
        source_ip,
        ttl,
        type_of_service,
      },
      package_type,
      payload,
      push_flag,
      reset_flag,
      sequence_number,
      source_port,
      synchronize_flag,
      urgent_flag,
      urgent_pointer,
      window,
  } = packet;

  return (
    <Card className={classes.card}>
      <CardContent>
        <Grid container spacing={2}>
          <Grid item xs={12} className={classes.centeredTitle}>
            { protocols[package_type] } Packet
            { payload &&
              <> 
                &nbsp;&nbsp;
                <Button
                  startIcon={<Sms />} 
                  onClick={() => { setOpenModalpayload(true); }}
                >
                  Payload
                </Button>
              </>
            }
          </Grid>
          <Grid item container xs={ protocols[package_type] === 'TCP' ? 4 : 6 }>
            <Card>
              <CardContent>
                <Grid container>
                  <Grid item xs={12} className={classes.centeredTitle}>
                    Ethernet Header
                  </Grid>
                  <Grid item xs={12} className={classes.centeredLeft}>
                    Destination Address: {destination_mac_address}
                  </Grid>
                  <Grid item xs={12} className={classes.centeredLeft}>
                    Source Address: {source_mac_address}
                  </Grid>
                  <Grid item xs={12} className={classes.centeredLeft}>
                    Protocol: {ethProtocol}
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          <Grid item container xs={ protocols[package_type] === 'TCP' ? 4 : 6 }>
            <Card>
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} className={classes.centeredTitle}>
                    IP Header
                  </Grid>
                  <Grid item container xs={6} className={classes.centered}>
                    <Grid item xs={12} className={classes.centeredLeft}>
                      IP Version: {ip_version}
                    </Grid>
                    <Grid item xs={12} className={classes.centeredLeft}>
                      IP Header Length: {ip_header_length}
                    </Grid>
                    <Grid item xs={12} className={classes.centeredLeft}>
                      Type of service: {type_of_service}
                    </Grid>
                    <Grid item xs={12} className={classes.centeredLeft}>
                      IP Total Length: {size_of_packet}
                    </Grid>
                    <Grid item xs={12} className={classes.centeredLeft}>
                      Identification: {identification}
                    </Grid>
                  </Grid>
                  <Grid item container xs={6}>
              <Grid item xs={12} className={classes.centeredLeft}>
                TTL: {ttl}
              </Grid>
              <Grid item xs={12} className={classes.centeredLeft}>
                Protocol: {protocol}
              </Grid>
              <Grid item xs={12} className={classes.centeredLeft}>
                Checksum: {ipChecksum}
              </Grid>
              <Grid item xs={12} className={classes.centeredLeft}>
                Source IP: {source_ip}
              </Grid>
              <Grid item xs={12} className={classes.centeredLeft}>
                Destination IP: {destination_ip}
              </Grid>
            </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
            { protocols[package_type] === 'TCP' &&
              <Grid item container xs={4}>
                <Card>
                  <CardContent>
                    <Grid container spacing={2}>
                      <Grid item xs={12} className={classes.centeredTitle}>
                        TCP Header
                      </Grid>
                        <>
                          <Grid item container xs={6}>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Source Port: {source_port}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Destination Port: {destination_port}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Sequence Number: {sequence_number}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Acknowledgement Number: {acknowledge_number}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Header Length: {header_length}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Window: {window}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Checksum: {checksum}
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Urgent Pointer: {urgent_pointer}
                            </Grid>
                          </Grid>
                          <Grid item container xs={6}>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              Flags:
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Urgent'}
                                checked={urgent_flag}
                              />
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Acknowledgement'}
                                checked={acknowledge_flag}
                              />
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Push'}
                                checked={push_flag}
                              />
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Reset'}
                                checked={reset_flag}
                              />
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Synchronise'}
                                checked={synchronize_flag}
                              />
                            </Grid>
                            <Grid item xs={12} className={classes.centeredLeft}>
                              &nbsp;&nbsp;
                              <TCPHeaderFlag 
                                flagText={'Finish'}
                                checked={finish_flag}
                              />
                            </Grid>
                          </Grid>
                        </>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid> }
        </Grid>
      </CardContent>
      <PayloadModal
        open={openModalPayload}
        closeModal={ () => setOpenModalpayload(false) }
      >
        {payload}
      </PayloadModal>
    </Card>
  );

};

Packet.propTypes = {
  packet: PropTypes.object.isRequired,
};

export default Packet;
