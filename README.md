# x3dh

[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Build Status](https://semaphoreci.com/api/v1/florianlenz/x3dh/branches/master/badge.svg)](https://semaphoreci.com/florianlenz/x3dh)

> An x3dh implementation.

This is an almost complete implementation of the [x3dh](https://signal.org/docs/specifications/x3dh/) key agreement protocol. However, there are a few things that you need to take care of yourself:
1. If you fetch a preKeyBundle (holds information about the person you would like to chat with, like the identity key, etc) you have to check the signature yourself. It's not built into the code. We only "ask you" IF the key is valid. You can then say yes/no. If you say no, the protocol will be aborted.
2. You are responsible for handling the intital message (and the encoding), we only give you the calculated secret + the ephemeral key generated during the protocol run.
3. Currently we only support curve25519 (but you can implement the `Curve` interface in order to use another curve).

## Table of Contents

- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Security
If you find a security bug/ vulnerability please DO NOT open an issue. Write to security@bitnation.co PLEASE use [this](security-bitnation.co.key.pub) PGP key to encrypt your report / email.

## Install

```
go get github.com/Bit-Nation/x3dh
```
It might make sense to chose a dependency manager of your choise to pin the version to a specific commit.

## Usage

```
// create an instance of the curve util
c := &Curve25519{}

// make sure ot save this somewhere
myKeyPair, err := c.GenerateKeyPair()

x := x3dh.New(c, sha256.New(), "test", myKeyPair)

```

## API
The following methods are available:
- `CalculateSecret` calculate a secret based on your Idkey and a received PreKeyBundle.
- `SecretFromRemote` create a secret based on the received intial data.

## Maintainers

[@florianlenz](https://github.com/florianlenz)

## Contribute

Pull requests are accepted.

Small note: If editing the README, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specifications.

## License

MIT © 2018 Bitnation
