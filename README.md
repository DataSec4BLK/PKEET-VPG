# PKEET-VPG
Pure Go implementation for Public Encryption with Equality Test and Verifiable Public Generator (PKEET-VPG).

## Usage

### Benchmark for PKEET-VPG

All the codes are tested on both Mac and Ubuntu platforms with Go1.24.

- Mac Studio (M1 Max, 64GB RAM, macOS 15.0)

- Ubuntu Server (Intel(R) Xeon(R) Gold 6230, 125GB RAM, Ubuntu 20.04.6 LTS)

To run the basic test and benchmark for PKEET-VPG, enter the folder `PKEET-VGP-II` and run `go test` and `go test -bench=.` respectively.

To test the cost for record retrieval with different hyperparameters, run the function `main` in `pkeet-vpg.go` 

### Comparison with other schemes

We also implemented several related schemes and compared the communication and computation cost with our scheme, including:
- Hades[^1]
- SCN2022[^2]
- ElGamal[^3]
- DSup[^4]
- PKEOET[^5]

The Codes are in the `Comp` folder.


## Note

**This library is the code for paper entitled "Regulator-friendly Traceable Anonymous Credentials with Secure Outsourceable Record Retrieval"**


## Reference

[^1]: Wang, Ke, Jianbo Gao, Qiao Wang, Jiashuo Zhang, Yue Li, Zhi Guan, and Zhong Chen. "Hades: Practical decentralized identity with full accountability and fine-grained sybil-resistance." In Proceedings of the 39th Annual Computer Security Applications Conference, pp. 216-228. 2023.
[^2]: Hébant, Chloé, and David Pointcheval. "Traceable Constant-Size Multi-authority Credentials." In SCN 2022-13th conference on security and cryptography for networks, vol. 13409, pp. 411-434. Springer International Publishing, 2022.
[^3]: Zhou, Xiaotong, Debiao He, Jianting Ning, Min Luo, and Xinyi Huang. "AADEC: Anonymous and auditable distributed access control for edge computing services." IEEE Transactions on Information Forensics and Security 18 (2022): 290-303.
[^4]: Jia, Meng, et al. "Multi-Authority Anonymous Credentials With Efficient and Decentralized Supervision." IEEE Transactions on Information Forensics and Security (2025).
[^5]: Ma, Sha, Yijian Zhong, and Qiong Huang. "Efficient public key encryption with outsourced equality test for cloud-based IoT environments." IEEE Transactions on Information Forensics and Security 17 (2022): 3758-3772.


