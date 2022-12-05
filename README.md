<h1 align="center">EE392/EE491 B.Tech Project (BTP)</h1>

With the advent of the new internet age, internet connectivity has become an integral part of everyone’s life. Whether banking, shopping, or other day-to-day activities, they are all now run on the internet. Because of easily available internet facilities in many countries, small, low-powered devices connected to the internet have become quite common. The interconnection of such devices is called the Internet of Things (IoT), and these devices are then called IoT devices. The advantage of these devices is the remote access they provide to the user. One particularly important use case is the Smart Metering infrastructure.

In this project we set out to study the Smart Metering infrastructure, specially the ones using LoRaWAN as a communication protocol and did a deep dive to figure out any security vulnerablities and their countermeasures. We discovered bit-flipping as a weakness and suggested the countermeasure as implementing AES-128 in Galois Counter Mode to insert GMAC for authentication of ciphertext(s).