# SmaEnergyMeter
Java class to access data on a SMA energy metert or SMA home manager
It uses no external dependencies.

It will create a permanent multicast connection running in a background thread.
The connection is hardened to be used also over Wifi connections. When the connection fails, it will auto reconnect after 30 sec. That being said using wifi is not recommended because in real life you'll many reconnects (every few minutes).
At any time you can invoke the getCurrentData method to get the latest received data.
Also the getSerials will return an Long[] of all SMA serials it encountered.

The smaResponseData class contains the following:
- serial number (long)
- power3f (BigDecimal): power in Watt for all 3 phases
- powerL1 (BigDecimal): power in Watt for all phase 1
- powerL2 (BigDecimal): power in Watt for all phase 2
- powerL3 (BigDecimal): power in Watt for all phase 3

Typical use:

```java
    public static void main(String[] args) throws InterruptedException {
        SmaEnergyMeter smaEnergyMeter = new SmaEnergyMeter();
        smaEnergyMeter.establishConnection();
        int counter = 0;
        while (counter < 10) {
            SmaEnergyMeter.SmaResponseData[] array = smaEnergyMeter.getCurrentData();
            for (SmaEnergyMeter.SmaResponseData data : array) {  // iterate over array to avoid ConcurrentModificationException
                System.out.println("Power from serial nr " + data.serial + " is " + data.power3f + " Watt");
            }
            Thread.sleep(1000);
            counter++;
        }
        System.out.print("\nEncountered serial(s) are: ");
        Long[] array = smaEnergyMeter.getSerials();
        for (Long data : array) {
            System.out.print(data + ", ");
        }
        System.out.print("\nClosing... ");
        smaEnergyMeter.closeConnection();
        System.out.println("done");
    }
```
