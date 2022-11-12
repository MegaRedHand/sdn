[![Tests](https://github.com/MegaRedHand/sdn/actions/workflows/tests.yml/badge.svg)](https://github.com/MegaRedHand/sdn/actions/workflows/tests.yml) [![Linter](https://github.com/MegaRedHand/sdn/actions/workflows/linter.yml/badge.svg)](https://github.com/MegaRedHand/sdn/actions/workflows/linter.yml)

# TP2 - Software-Defined Networks

## Introducción

Segundo trabajo práctico de la materia Introducción a los sistemas distribuidos de la Facultad de Ingeniería de la Universidad de Buenos Aires.

Integrantes del grupo:
 - Grüner, Tomás
 - Gonzalez, Matias Ignacio
 - Sotelo Guerreño, Lucas Nahuel
 - Pareja, Facundo Jose
 - D’Alessandro Szymanowski, Sebastián Javier

## Instalación

### Dependencias:
* [python3.10^](https://www.python.org/downloads/)
* [Poetry](https://python-poetry.org/docs/#installation)

Una vez instaladas estas herramientas, make se encargará del resto :relieved:

``` bash
$ make install
```

## Ejecución

## Ejecutar formatters y linter

Este repositorio usa GitHub Workflows para correr un linter en cada push o pull request.
Para correr el formatter o linter manualmente se puede usar el siguiente comando:

``` bash
$ make lint
```

## Ejecutar test

Comenzar lanzando el modulo firewall de Pox

```
./pox.py firewall
```

Lanzar Mininet con controlador remoto

```
sudo mn --custom ./src/topo.py --topo xwing --controller=remote,ip=127.0.0.1,port=6633
```

O tambien se puede ejecutar un test (pingall) con 

```
sudo mn --custom ./src/topo.py --topo xwing --controller=remote,ip=127.0.0.1,port=6633 --test pingall
```

## Configuracion de reglas

El archivo *reglas.txt* *(src/pox)* permite rapida configuracion de reglas

Las posibilidades son:

```
BLOCK_PORT port_number
```

para blockear cualquier paquete dirigidos al puerto port_number

```
BLOCK_TRAFFIC host1_number host2_number
```

para blockear todo el trafico entre 2 hosts de direcciones 10.0.0.host1_number
y 10.0.0.host2_number.

```
BLOCK_PORT_HOST_PROTOCOL port_number host_number protocol_number
```

para bloquear los paquetes provenientes del host 10.0.0.host_number con protocolo
protocol_number (por ejemplo 17 para TCP y 6 para UDP) y dirigidos al puerto port_number.