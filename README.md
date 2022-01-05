# The KHAPE key exchange protocol

[KHAPE](https://eprint.iacr.org/2021/873.pdf) is an asymmetric password-authenticated key exchange (PAKE) protocol. It allows a client to authenticate to a server using a password, without ever having to expose the plaintext password to the server.



## Project

This project is part of my [bachelor thesis](https://github.com/jul0105/Bachelor-Thesis/raw/master/report.pdf). The goal of it was to study the existing PAKEs protocol and to implement one. KHAPE was chosen because it provide the highest level of security among PAKEs protocol and it is very recent.



## Disclaimer

This library was implemented for educational purpose. Use at your how risk.



## Usage

To use this library, you need to add the followings entries to your `Cargo.toml` :

```toml
[dependencies]
khape = { version = "0.1.0", git = "https://github.com/jul0105/KHAPE.git" }
```

And also :

```toml
[patch.crates-io]
curve25519-dalek = { git = "https://github.com/jul0105/curve25519-dalek.git" }
```

The patch is required because this library uses a customized version of `curve25519-dalek` to implement Elligator2 decoding on Montgomery curves.



## Use case

A prototype of an online password manager using KHAPE for the authentication can be found [here](https://github.com/jul0105/OnlinePasswordManager).



## Documentation

Documentation is available by executing the following command :

```
cargo doc --no-deps --open
```

## Benchmark

Benchmarks can be computed with the following command : 

```
cargo bench --features "bench"
```
