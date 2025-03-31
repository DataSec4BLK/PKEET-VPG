# PKEET-VPG
Pure Go implementation for Public Encryption with Equality Test and Verifiable Public Generator (PKEET-VPG).

## Usage

### Benchmark for PKEET-VPG

All the codes are tested on both Mac and Ubuntu platforms with Go1.24.

- Mac Studio (M1 Max, 64GB RAM, macOS 15.0)

- Ubuntu Server (Intel(R) Xeon(R) Gold 6230, 125GB RAM, Ubuntu 20.04.6 LTS)

To run the basic test for PKEET-VPG, run the function `BasicTest` in `pkeetvpg.go`.

To test the cost for record tracing with different sizes, run the function `BatchTraceTest` in `pkeetvpg.go` 

### Comparison with other schemes

We also implemented several related schemes and compared the communication and computation cost with our scheme, including:
- Hades[^1]
- Sanitize[^2]
- SCN2022[^3]
- ElGamal[^4]

The Codes are in the `Comp` folder.


## Warning

**This library is not ready for production use!**


## Reference

[^1]: Wang, Ke, Jianbo Gao, Qiao Wang, Jiashuo Zhang, Yue Li, Zhi Guan, and Zhong Chen. "Hades: Practical decentralized identity with full accountability and fine-grained sybil-resistance." In Proceedings of the 39th Annual Computer Security Applications Conference, pp. 216-228. 2023.
[^2]: Canard, Sébastien, and Roch Lescuyer. "Protecting privacy by sanitizing personal data: a new approach to anonymous credentials." In Proceedings of the 8th ACM SIGSAC symposium on Information, computer and communications security, pp. 381-392. 2013.
[^3]: Hébant, Chloé, and David Pointcheval. "Traceable Constant-Size Multi-authority Credentials." In SCN 2022-13th conference on security and cryptography for networks, vol. 13409, pp. 411-434. Springer International Publishing, 2022.
[^4]: Zhou, Xiaotong, Debiao He, Jianting Ning, Min Luo, and Xinyi Huang. "AADEC: Anonymous and auditable distributed access control for edge computing services." IEEE Transactions on Information Forensics and Security 18 (2022): 290-303.


