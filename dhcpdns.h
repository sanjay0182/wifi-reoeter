// dhcpdns.h - DHCP DNS set helper (ESP8266 core ke alag version ke liye)
// Template yahan alag file me hai, kyunki Arduino .ino me template ke prototype galat bana deta hai.
#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <lwip/netif.h>

template <int N> struct DPrio : DPrio<N - 1> {};
template <> struct DPrio<0> {};

template <class D>
auto dhcpSetOne(D &d, int n, uint32_t v, DPrio<5>) -> decltype(d.dhcps_set_dns(n, (const ip4_addr_t *)nullptr), void()) {
  ip4_addr_t x;
  x.addr = v;
  d.dhcps_set_dns(n, &x);
}
template <class D>
auto dhcpSetOne(D &d, int n, uint32_t v, DPrio<4>) -> decltype(d.setDns(n, (const ip4_addr_t *)nullptr), void()) {
  ip4_addr_t x;
  x.addr = v;
  d.setDns(n, &x);
}
template <class D>
auto dhcpSetOne(D &d, int n, uint32_t v, DPrio<3>) -> decltype(d.dhcps_set_dns(n, IPAddress()), void()) {
  d.dhcps_set_dns(n, IPAddress(v));
}
template <class D>
auto dhcpSetOne(D &d, int n, uint32_t v, DPrio<2>) -> decltype(d.setDns(n, IPAddress()), void()) {
  d.setDns(n, IPAddress(v));
}
// Kuch core me sirf 1 DNS set hota hai: setDns(IPAddress)
template <class D>
auto dhcpSetOne(D &d, int n, uint32_t v, DPrio<1>) -> decltype(d.setDns(IPAddress()), void()) {
  if (n == 0) d.setDns(IPAddress(v));
}
template <class D>
void dhcpSetOne(D &, int, uint32_t, DPrio<0>) {
  Serial.println("DHCP DNS set API nahi mili");
}

