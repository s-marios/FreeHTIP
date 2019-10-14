# FreeHTIP
This is the first public release of FreeHTIP, an open source implementation
of the HTIP protocol for microcontrollers. It provides both building and 
parsing HTIP frames. 

### Prerequisites
This software is expected to be used along with 
[*FreeRTOS*](https://www.freertos.org/) and 
[*lwip*](https://savannah.nongnu.org/projects/lwip/), 
although neither of these are hard dependencies and can be removed and/or 
substituted.

Support for *malloc* is neccessary.

### Tested Platforms 
Currently this impelmentation has been tested with the FRDM-K64F and ESP32
microcontrollers.

Setting up a project for a microcontroller is a platform-specific task; we
recommend that you setup a minimal project with networking functionallity
using your developer tools and then proceed to use the provided source 
code as is, modifying any inclusion header file paths.

### Getting Started
The file l2agent.c contains a sample implementation of what we expect is
to be a typical FreeRTOS task that periodically sends HTIP frames over the
network. Furthermore, it contains an example demonstrating how to create
an HTIP frame. Feel free to modify these to suit your needs.

### Source Code at GitHub
The latest source code for this project can be found at the project's
[GitHub page](https://github.com/s-marios/FreeHTIP)
