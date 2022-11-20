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

```bash
$ src/pox/pox.py firewall
```

Lanzar Mininet con controlador remoto

```bash
$ sudo mn --custom ./src/topo.py --topo xwing --mac --switch ovsk --controller=remote,ip=127.0.0.1,port=6633
```

Puede especificarse el número de switches de la topología luego del nombre, separado por una coma.
Por ejemplo, para 5 switches: `--topo xwing,5`

O tambien se puede ejecutar un test (pingall) con 

```bash
$ sudo mn --custom ./src/topo.py --topo xwing --mac --switch ovsk --controller=remote,ip=127.0.0.1,port=6633 --test pingall
```

## Configuracion de reglas

El firewall implementado permite una rápida configuración de reglas mediante la edición del archivo `src/pox/rules.txt`.
Alternativamente, puede especificarse otro archivo del cual tomar las reglas a través del parámetro `--rules-file`:

```bash
$ src/pox/pox.py firewall --rules-files=path/al/archivo
```

Las reglas disponibles son:

- Bloquear paquetes con un puerto destino de `port`

```
BLOCK_PORT port
```

- Bloquear todo el tráfico entre dos hosts (especificándolos con su dirección IP)

```
BLOCK_TRAFFIC ip_hos1 ip_host2
```

- Bloquear paquetes provenientes del host con ip `ip_host`,
de protocolo de transporte `protocol`, y puerto destino `port`

```
BLOCK_PORT_HOST_PROTOCOL port ip_host protocol
```
