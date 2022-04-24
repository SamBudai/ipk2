# Packet Sniffer

Sieťový analyzátor v jazyku C ktorý na určitom sieťovom rozhraní zachytáva a filtruje pakety. <br><br>
Po vytvorení spustiteľného programu pomocou príkazu `make`  alebo `make ipk-sniffer` sa program volá nasledovne:\
`./ipk-sniffer [-i rozhranie | --interface rozhranie] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`\
<br>
kde
- -i <rozhranie> (práve jedno rozhranie na ktorom sa bude počúvať. Ak nebude tento parametr uvedený, alebo bude uvedené len -i bez hodnoty, vypíše sa zoznam aktívnych rozhraní)
- -p <port> (bude filtrovanie paketov na danom rozhraní podľa portu; ak nebude tento parametr uvedený, uvažujú sa všetkyy porty; ak je parameter uvedený, môže se daný port vyskytnúť ako v source, tak v destination časti)
- -t alebo --tcp (bude zobrazovať iba TCP pakety)
- -u nebo --udp (bude zobrazovat iba UDP pakety)
- --icmp (bude zobrazovat iba ICMPv4 a ICMPv6 pakety)
- --arp (bude zobrazovat pouze ARP rámce)
  
### Príklady volania
- `./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp`
- `./ipk-sniffer -i eth0 -p 23 --tcp -n 2`
- `./ipk-sniffer -i eth0 --udp -n 21`
- `./ipk-sniffer -i eth0 --icmp` 
- `./ipk-sniffer -i eth0 --udp`   
- `./ipk-sniffer -i eth0 -n 10 `
- `./ipk-sniffer -i eth0 `
  
### Zoznam odovzdaných súborov
- main.c
- Makefile
- manual.pdf
- README.md
  
