
<a href="https://plus.google.com/105236054684418980818" rel="publisher"></a>
Copyright (c) 2013, 2014
    NES &lt;nes.open.switch@gmail.com&gt;

NES Open Switch
===============

NES Open Switch is a network protocol stack implementation. It functions as a
common control and management plane for transport networks. Still this
implementation is basically a bundle of modules which can be re-organized to
cater other classes of networks as well (e.g. enterprise or access networks),
but that is not in the scope of NES Open Switch.

The primary scope of NES Open Switch is the development of a protocol stack for
research and educational purposes. Industry standard protocols are bundled in
NES Open Switch, which can be extended for future development of these
technologies, so that new extensions can be rapidly prototyped. Only protocols
standardized by industry standard bodies (ISO, ITU-T, IETF) are implemented in
NES Open Switch. Proprietary extensions of the protocols are not the target for
NES Open Switch. Usage of this implementation in a production environment or
it's profitability are not the immediate focus of NES Open Switch.

NES Open Switch is capable of handling current network technologies like
Ethernet, SDH/Sonet, OTN and WDM. Some of these supporting modules are under
development. NES Open Switch provides static network management facility for
these technologies. NES Open Switch also supports the dynamic management of the
network through GMPLS.

NES Open Switch is built independent of the underlying network hardware. The
hardware interfacing is done through an hardware abstraction layer (HAL). The
HAL layer can be ported for different hardware platforms and that shall be
enough for controlling the prticular network hardware platform with NES Open
Switch. NES Open Switch is compatible with chassis or pizza-box type of network
devices.


Development
===========

NES Open Switch is always under continuous development cycle. Modules are
continuously getting developed and added to NES Open Switch. The author provides
routine bug fixes and updates. But others are also welcome in collabrating or
contributing in the development.
