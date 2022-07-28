package com.johanpmeert;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.*;

public class SmaEnergyMeter {

    private ArrayList<SmaResponseData> allResponseData = new ArrayList();
    private ArrayList<Long> serials = new ArrayList();
    private volatile boolean closeConnectionCalled = false;
    private boolean logging = true;
    private Logger logger = Logger.getLogger("LogSma");

    public SmaEnergyMeter() {
    }

    public SmaEnergyMeter(boolean logging) {
        this.logging = logging;
    }

    public SmaResponseData[] getCurrentData() {
        return allResponseData.toArray(new SmaResponseData[0]);
    }

    public Long[] getSerials() {
        return serials.toArray(new Long[0]);
    }

    public void establishConnection() {
        Thread newThread = new Thread(new SmaThread("sma" + (int) (Math.random() * 10000)));
        newThread.start();
    }

    public void closeConnection() {
        closeConnectionCalled = true;
    }

    public static class SmaResponseData {
        long serial = 0;
        BigDecimal power3f = BigDecimal.ZERO;
        BigDecimal rpower3f = BigDecimal.ZERO;
        BigDecimal apower3f = BigDecimal.ZERO;
        BigDecimal powerL1 = BigDecimal.ZERO;
        BigDecimal currentL1 = BigDecimal.ZERO;
        BigDecimal voltageL1 = BigDecimal.ZERO;
        BigDecimal powerL2 = BigDecimal.ZERO;
        BigDecimal currentL2 = BigDecimal.ZERO;
        BigDecimal voltageL2 = BigDecimal.ZERO;
        BigDecimal powerL3 = BigDecimal.ZERO;
        BigDecimal currentL3 = BigDecimal.ZERO;
        BigDecimal voltageL3 = BigDecimal.ZERO;
        String ipAddress = "";
    }

    private class SmaThread implements Runnable {

        private String threadName;

        SmaThread(String name) {
            threadName = name;
        }

        @Override
        public void run() {
            if (logging) {
                FileHandler fh = null;
                try {
                    fh = new FileHandler("sma.log");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                logger.addHandler(fh);
                // Override the standard formatter to something on 1 line
                Formatter formatter = new Formatter() {
                    @Override
                    public String format(LogRecord arg0) {
                        return new Date() + ", " + arg0.getLevel() + ": " + arg0.getMessage() + System.getProperty("line.separator");
                    }
                };
                fh.setFormatter(formatter);
                // also set the console logger to the new formatter
                Logger globalLogger = Logger.getLogger("");
                Handler[] handlers = globalLogger.getHandlers();
                for (Handler handler : handlers) {
                    handler.setFormatter(formatter);
                }
            }
            final String SMA_MULTICAST_IP = "239.12.255.254";
            final int SMA_MULTICAST_PORT = 9522;
            final long WATCHDOG_INTERVAL = 30000000000L; // 30 seconds
            String myHostIpAddress = getIpAddress();
            while (!closeConnectionCalled) {
                try {
                    InetAddress inetAddress = InetAddress.getByName(SMA_MULTICAST_IP);
                    InetSocketAddress inetSocketAddress = new InetSocketAddress(inetAddress, SMA_MULTICAST_PORT);
                    NetworkInterface networkInterface = NetworkInterface.getByName(myHostIpAddress);
                    MulticastSocket multicastSocket = new MulticastSocket(SMA_MULTICAST_PORT);
                    multicastSocket.joinGroup(inetSocketAddress, networkInterface);
                    if (logging)
                        logger.info("MultiCast socket opened on " + SMA_MULTICAST_IP + ":" + SMA_MULTICAST_PORT);
                    final byte[] txbuf = hexStringToByteArray("534d4100000402a0ffffffff0000002000000000");  // discovery string to be sent to network, all SMA devices will answer
                    DatagramPacket datagramPacket = new DatagramPacket(txbuf, txbuf.length, inetAddress, SMA_MULTICAST_PORT);
                    multicastSocket.send(datagramPacket);
                    byte[] buffer = new byte[1024];
                    datagramPacket = new DatagramPacket(buffer, buffer.length);
                    long watchDog = System.nanoTime();
                    while (!closeConnectionCalled && ((System.nanoTime() - watchDog) < WATCHDOG_INTERVAL)) { // 30 sec watchdog check
                        multicastSocket.receive(datagramPacket);
                        byte[] slice = Arrays.copyOfRange(buffer, 0, datagramPacket.getLength());
                        SmaResponseData smaResponseData = parseSmaResponse(slice);
                        if (smaResponseData != null) {
                            if (!serials.contains(smaResponseData.serial)) {  // serial first reception
                                serials.add(smaResponseData.serial); // add serial to list of serials
                                logger.info("Found new serial " + smaResponseData.serial);
                            } else {
                                watchDog = System.nanoTime(); // reset the watchdog
                                allResponseData.removeIf(x -> x.serial == smaResponseData.serial); // delete the old data with this serial nr
                            }
                            smaResponseData.ipAddress = String.valueOf(datagramPacket.getAddress());
                            allResponseData.add(smaResponseData); // add data to list
                        }
                    }
                    if (closeConnectionCalled) {
                        logger.info("Close connection called");
                    } else {
                        logger.warning("Watchdog timer exceeded, auto restarting connection");
                    }
                    multicastSocket.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private SmaResponseData parseSmaResponse(byte[] hexData) {
        // Extracting the correct values from the measurement byte[]
        // Up to now (2020) it is 600 or 608 bytes long: 600 for SMA energy meter and 608 for the SMA home manager 2
        // To be as futureproof as possible, we do not use the data byte offsets given by SMA (since they already changed once with a firmware update)
        // For the measurement we search the hexData for a specific marker and then extract the data from 4 to 8 bytes further
        // These markers, the offset data position and teh data length are stored in the enum internalData
        if (hexData.length < 600) return null;
        SmaResponseData smaData = new SmaResponseData();
        // the serial number is extracted direct from byte 20 to 24, then converted to an unsigned long
        // int is too short and would give negative serial numbers for some devices
        int serial = ByteBuffer.wrap(Arrays.copyOfRange(hexData, 20, 24)).getInt();
        smaData.serial = Integer.toUnsignedLong(serial);
        // Power is read relative to a marker position, but for every value there are 2 markers
        // one for the positive power, one for the negative
        // at least one of them is always zero
        // also, the power is stored in 0.1W numbers, so we need to divide by 10 to get the value in Watts
        // to make searching the marker position easier to program, we convert the byte[] to a hexString and look for the markers in this String
        // the extraction is done from the byte[] with the search result from above (divided by 2)
        // for correctness, the result is stored in a BigDecimal
        // voltage is encoded in 0.001V, we output in Volt
        // amps is encoded in 0.001A, we output in amps
        int power3fp = getValueFromMarker(hexData, internalData.power3fpos);
        int power3fn = getValueFromMarker(hexData, internalData.power3fneg);
        if (power3fp != 0) {
            smaData.power3f = BigDecimal.valueOf(power3fp).movePointLeft(1);
        } else {
            smaData.power3f = BigDecimal.valueOf(-power3fn).movePointLeft(1);
        }
        int powerR3fp = getValueFromMarker(hexData, internalData.rpower3fpos);
        int powerR3fn = getValueFromMarker(hexData, internalData.rpower3fneg);
        if (powerR3fp != 0) {
            smaData.rpower3f = BigDecimal.valueOf(powerR3fp).movePointLeft(1);
        } else {
            smaData.rpower3f = BigDecimal.valueOf(-powerR3fn).movePointLeft(1);
        }
        int powerA3fp = getValueFromMarker(hexData, internalData.apower3fpos);
        int powerA3fn = getValueFromMarker(hexData, internalData.apower3fneg);
        if (powerA3fp != 0) {
            smaData.apower3f = BigDecimal.valueOf(powerA3fp).movePointLeft(1);
        } else {
            smaData.apower3f = BigDecimal.valueOf(-powerA3fn).movePointLeft(1);
        }
        int powerL1p = getValueFromMarker(hexData, internalData.powerL1pos);
        int powerL1n = getValueFromMarker(hexData, internalData.powerL1neg);
        if (powerL1p != 0) {
            smaData.powerL1 = BigDecimal.valueOf(powerL1p).movePointLeft(1);
            smaData.currentL1 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.currentL1)).movePointLeft(3);
        } else {
            smaData.powerL1 = BigDecimal.valueOf(-powerL1n).movePointLeft(1);
            smaData.currentL1 = BigDecimal.valueOf(-getValueFromMarker(hexData, internalData.currentL1)).movePointLeft(3);
        }
        int powerL2p = getValueFromMarker(hexData, internalData.powerL2pos);
        int powerL2n = getValueFromMarker(hexData, internalData.powerL2neg);
        if (powerL2p != 0) {
            smaData.powerL2 = BigDecimal.valueOf(powerL2p).movePointLeft(1);
            smaData.currentL2 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.currentL2)).movePointLeft(3);
        } else {
            smaData.powerL2 = BigDecimal.valueOf(-powerL2n).movePointLeft(1);
            smaData.currentL2 = BigDecimal.valueOf(-getValueFromMarker(hexData, internalData.currentL2)).movePointLeft(3);
        }
        int powerL3p = getValueFromMarker(hexData, internalData.powerL3pos);
        int powerL3n = getValueFromMarker(hexData, internalData.powerL3neg);
        if (powerL3p != 0) {
            smaData.powerL3 = BigDecimal.valueOf(powerL3p).movePointLeft(1);
            smaData.currentL3 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.currentL3)).movePointLeft(3);
        } else {
            smaData.powerL3 = BigDecimal.valueOf(-powerL3n).movePointLeft(1);
            smaData.currentL3 = BigDecimal.valueOf(-getValueFromMarker(hexData, internalData.currentL3)).movePointLeft(3);
        }
        smaData.voltageL1 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.voltageL1)).movePointLeft(3);
        smaData.voltageL2 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.voltageL2)).movePointLeft(3);
        smaData.voltageL3 = BigDecimal.valueOf(getValueFromMarker(hexData, internalData.voltageL3)).movePointLeft(3);
        return smaData;
    }

    private int getValueFromMarker(byte[] hexData, internalData marker) {
        String hexDataString = byteArrayToHexString(hexData);
        int markerLocation = hexDataString.indexOf(marker.code);
        if (markerLocation == -1) return 0;
        markerLocation = markerLocation / 2;
        return ByteBuffer.wrap(Arrays.copyOfRange(hexData, markerLocation + marker.offset, markerLocation + marker.offset + marker.length)).getInt();
    }

    private enum internalData {
        // These are the 4 byte markers in hex:
        //
        // total power +
        // total power -
        // reactive power +
        // reactive power -
        // apparent power +
        // apparent power -
        // L1 total power +
        // L1 total power -
        // L1 current
        // L1 voltage
        // ...
        //
        power3fpos("00010400", 4, 4),
        power3fneg("00020400", 4, 4),
        rpower3fpos("00030400", 4, 4),
        rpower3fneg("00040400", 4, 4),
        apower3fpos("00090400", 4, 4),
        apower3fneg("000A0400", 4, 4),
        powerL1pos("00150400", 4, 4),
        powerL1neg("00160400", 4, 4),
        currentL1("001F0400", 4, 4),
        voltageL1("00200400", 4, 4),
        powerL2pos("00290400", 4, 4),
        powerL2neg("002A0400", 4, 4),
        currentL2("00330400", 4, 4),
        voltageL2("00340400", 4, 4),
        powerL3pos("003D0400", 4, 4),
        powerL3neg("003E0400", 4, 4),
        currentL3("00470400", 4, 4),
        voltageL3("00480400", 4, 4);

        final String code;
        final int offset;
        final int length;

        internalData(String code, int offset, int length) {
            this.code = code;
            this.offset = offset;
            this.length = length;
        }
    }

    private String getIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr.isSiteLocalAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
            return "";
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] hexStringToByteArray(String hex) {
        if (hex == null) return new byte[0];
        if (!hex.matches("[0-9A-Fa-f]+")) throw new IllegalArgumentException("Not a hex String");
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) return "";
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
