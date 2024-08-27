# DogeVPN

<a>
  <img src="documentation/img/unive.png" alt="logo" title="CaFoscari" align="right" height="100" />
</a>

Authors: 
- Andrea Gentilini [880141@stud.unive.it](880141@stud.unive.it)
- Mattia Dei Rossi [885768@stud.unive.it](885768@stud.unive.it)
- Giacomo Civiero [877378@stud.unive.it](877378@stud.unive.it)
- Simone Biondo [879899@stud.unive.it](879899@stud.unive.it)

## Introduction
<img src="documentation/img/Doge's_Crown2.png" alt="logo" title="DogeCrown" height="100" />

Implementing a well-managed virtual private network (VPN) is not as simple as it might seem. There are several caveats to consider and several ways to make the entire application non-resilient. Of course there are several pieces of complex code, appropriately packaged, that can help with some effort to build a functional VPN, but how the network works depends on the implementers. For this reason DogeVPN aims to be a simple but functional VPN, with almost all the features of a production-ready VPN. DogeVPN was born from a university project at Ca' Foscari University

## How to build and run using docker compose
Build
```bash
docker compose build
```
Allow Qt based GUI to be shown
```bash
xhost +local:docker
```
Run
```bash
docker compose up -d
```
