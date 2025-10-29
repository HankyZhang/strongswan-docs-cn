# VPN密码算法和密钥使用详解

> 本文档详细列出 IPsec VPN（基于 strongSwan IKEv2）完整协商和通信过程中使用的所有密码算法和密钥，包括密钥类型（对称/非对称）、使用方向、加密/解密方等信息。

---

## 目录

1. [VPN 协商阶段概览](#1-vpn-协商阶段概览)
2. [提案中的密码算法清单](#2-提案中的密码算法清单)
3. [密钥详细使用说明](#3-密钥详细使用说明)
4. [密钥生命周期管理](#4-密钥生命周期管理)
5. [国密算法支持](#5-国密算法支持)
6. [完整流程示例](#6-完整流程示例)

---

## 1. VPN 协商阶段概览

IPsec VPN 建立过程分为以下几个阶段：

```

                    IKE_SA_INIT 阶段                          
  - 交换 DH 公钥                                              
  - 协商加密算法、PRF、完整性算法、DH 组                        
  - 生成 SKEYSEED 和 IKE 密钥材料                              

                            

                    IKE_AUTH 阶段                             
  - 使用非对称密钥进行身份认证（RSA/ECDSA/SM2）                
  - 协商 ESP 加密算法和完整性算法                              
  - 生成 CHILD_SA 密钥材料                                     

                            

                    ESP 数据传输阶段                           
  - 使用对称密钥加密和认证数据包                                
  - 双向独立的密钥（发起方和响应方各自的加密/认证密钥）          

```

---

## 2. 提案中的密码算法清单

### 2.1 IKE_SA_INIT 提案算法

#### **IKE 提案（IKE Proposal）**

| 算法类型 | 算法选项 | 说明 |
|---------|---------|-----|
| **加密算法 (ENCR)** | AES-CBC-128<br>AES-CBC-256<br>AES-GCM-128<br>AES-GCM-256<br>**SM4-CBC**<br>**SM4-GCM**<br>3DES<br>CHACHA20-POLY1305 | 用于加密 IKE 消息（从 IKE_AUTH 开始）<br>**粗体**为国密算法 |
| **伪随机函数 (PRF)** | PRF-HMAC-SHA1<br>PRF-HMAC-SHA256<br>PRF-HMAC-SHA384<br>PRF-HMAC-SHA512<br>**PRF-HMAC-SM3** | 用于密钥派生<br>**粗体**为国密算法 |
| **完整性算法 (INTEG)** | HMAC-SHA1-96<br>HMAC-SHA256-128<br>HMAC-SHA384-192<br>HMAC-SHA512-256<br>**HMAC-SM3**<br>AES-XCBC-96 | 用于 IKE 消息认证<br>GCM 模式下可省略<br>**粗体**为国密算法 |
| **DH 组 (DH)** | MODP-1024 (Group 2)<br>MODP-1536 (Group 5)<br>MODP-2048 (Group 14)<br>MODP-3072 (Group 15)<br>MODP-4096 (Group 16)<br>ECP-256 (Group 19)<br>ECP-384 (Group 20)<br>ECP-521 (Group 21)<br>**SM2 Curve** | Diffie-Hellman 密钥交换组<br>**粗体**为国密算法 |

**strongSwan 配置示例**：

```bash
# swanctl.conf
connections {
  vpn {
    proposals = aes256-sha256-modp2048,sm4cbc-sm3-sm2
    # 格式：加密算法-完整性算法(PRF)-DH组
  }
}
```

### 2.2 IKE_AUTH 认证算法

#### **认证算法（Authentication）**

| 算法名称 | 签名算法 | 哈希算法 | 密钥类型 | 说明 |
|---------|---------|---------|---------|-----|
| RSA-SHA1 | RSA | SHA1 | 非对称 | 传统 RSA 签名（不推荐） |
| RSA-SHA256 | RSA | SHA256 | 非对称 | 推荐的 RSA 签名 |
| RSA-SHA384 | RSA | SHA384 | 非对称 | 高强度 RSA 签名 |
| RSA-SHA512 | RSA | SHA512 | 非对称 | 高强度 RSA 签名 |
| ECDSA-SHA256 | ECDSA | SHA256 | 非对称 | ECC 签名（P-256） |
| ECDSA-SHA384 | ECDSA | SHA384 | 非对称 | ECC 签名（P-384） |
| **SM2-SM3** | **SM2** | **SM3** | **非对称** | **国密签名算法** |
| PSK (Pre-Shared Key) | HMAC | PRF | 对称 | 预共享密钥认证 |

**strongSwan 配置示例**：

```bash
connections {
  vpn {
    local {
      auth = pubkey           # 公钥认证（RSA/ECDSA/SM2）
      # 或 auth = psk        # 预共享密钥认证
    }
  }
}
```

### 2.3 CHILD_SA (ESP) 提案算法

#### **ESP 提案（ESP Proposal）**

| 算法类型 | 算法选项 | 说明 |
|---------|---------|-----|
| **加密算法 (ENCR)** | AES-CBC-128<br>AES-CBC-256<br>AES-GCM-128<br>AES-GCM-256<br>AES-CTR-128<br>AES-CTR-256<br>**SM4-CBC**<br>**SM4-GCM**<br>3DES<br>CHACHA20-POLY1305<br>NULL（仅认证） | 用于加密 ESP 数据包<br>**粗体**为国密算法 |
| **完整性算法 (INTEG)** | HMAC-SHA1-96<br>HMAC-SHA256-128<br>HMAC-SHA384-192<br>HMAC-SHA512-256<br>**HMAC-SM3**<br>AES-XCBC-96<br>AES-CMAC-96 | 用于 ESP 数据包认证<br>GCM 模式下可省略<br>**粗体**为国密算法 |
| **扩展序列号 (ESN)** | ESN<br>NO-ESN | 扩展序列号支持（防重放） |
| **PFS DH 组** | 同 IKE DH 组 | Perfect Forward Secrecy（可选） |

**strongSwan 配置示例**：

```bash
connections {
  vpn {
    children {
      net {
        esp_proposals = aes256gcm128-modp2048,sm4gcm-sm2
        # 格式：加密算法-完整性算法-DH组（PFS）
      }
    }
  }
}
```

---

## 3. 密钥详细使用说明

### 3.1 IKE_SA_INIT 阶段密钥

#### **3.1.1 DH 密钥对（Diffie-Hellman Key Pair）**

| 密钥名称 | 密钥类型 | 所有者 | 用途 | 生命周期 |
|---------|---------|-------|------|---------|
| DH_i_private | 非对称（私钥） | 发起方 | 生成共享密钥 | 临时（交换后销毁） |
| DH_i_public | 非对称（公钥） | 发起方 | 发送给响应方 | 临时 |
| DH_r_private | 非对称（私钥） | 响应方 | 生成共享密钥 | 临时（交换后销毁） |
| DH_r_public | 非对称（公钥） | 响应方 | 发送给发起方 | 临时 |

**流程**：

```
发起方：
  1. 生成 DH_i_private、DH_i_public
  2. 发送 DH_i_public  响应方
  3. 接收 DH_r_public  响应方
  4. 计算：g^(DH_i_private * DH_r_public) = 共享密钥 (g^ab)

响应方：
  1. 生成 DH_r_private、DH_r_public
  2. 接收 DH_i_public  发起方
  3. 发送 DH_r_public  发起方
  4. 计算：g^(DH_r_private * DH_i_public) = 共享密钥 (g^ab)
```

#### **3.1.2 SKEYSEED 和 IKE 密钥材料**

| 密钥名称 | 密钥类型 | 长度 | 生成方 | 用途 |
|---------|---------|-----|-------|------|
| SKEYSEED | 对称 | PRF 输出长度 | 双方独立计算 | 根密钥种子 |
| SK_d | 对称 | PRF 输出长度 | 从 SKEYSEED 派生 | 派生 CHILD_SA 密钥 |
| SK_ai | 对称 | INTEG 密钥长度 | 从 SKEYSEED 派生 | 发起方响应方 IKE 消息认证 |
| SK_ar | 对称 | INTEG 密钥长度 | 从 SKEYSEED 派生 | 响应方发起方 IKE 消息认证 |
| SK_ei | 对称 | ENCR 密钥长度 | 从 SKEYSEED 派生 | 发起方响应方 IKE 消息加密 |
| SK_er | 对称 | ENCR 密钥长度 | 从 SKEYSEED 派生 | 响应方发起方 IKE 消息加密 |
| SK_pi | 对称 | PRF 输出长度 | 从 SKEYSEED 派生 | 发起方 AUTH 载荷生成 |
| SK_pr | 对称 | PRF 输出长度 | 从 SKEYSEED 派生 | 响应方 AUTH 载荷生成 |

**派生公式**：

```
SKEYSEED = prf(Ni | Nr, g^ir)
  其中：Ni = 发起方随机数，Nr = 响应方随机数，g^ir = DH 共享密钥

{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = 
  prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
```

**使用方向**：

```
发起方发送 IKE 消息：
  - 使用 SK_ei 加密
  - 使用 SK_ai 计算 HMAC

响应方接收 IKE 消息：
  - 使用 SK_ei 解密
  - 使用 SK_ai 验证 HMAC

响应方发送 IKE 消息：
  - 使用 SK_er 加密
  - 使用 SK_ar 计算 HMAC

发起方接收 IKE 消息：
  - 使用 SK_er 解密
  - 使用 SK_ar 验证 HMAC
```

### 3.2 IKE_AUTH 阶段密钥

#### **3.2.1 证书和私钥（公钥认证）**

| 密钥名称 | 密钥类型 | 所有者 | 用途 | 谁签名 | 谁验证 |
|---------|---------|-------|------|-------|-------|
| Initiator_Private_Key | 非对称（私钥） | 发起方 | 签名 AUTH_i | 发起方 | - |
| Initiator_Public_Key | 非对称（公钥） | 发起方（证书中） | 验证签名 | - | 响应方 |
| Responder_Private_Key | 非对称（私钥） | 响应方 | 签名 AUTH_r | 响应方 | - |
| Responder_Public_Key | 非对称（公钥） | 响应方（证书中） | 验证签名 | - | 发起方 |

**认证流程**：

```
发起方认证（生成 AUTH_i）：
  1. 计算 InitiatorSignedOctets = RealMessage1 | Nr | prf(SK_pi, IDi')
  2. 使用 SHA256 计算哈希：Hash = SHA256(InitiatorSignedOctets)
  3. 使用发起方私钥签名：AUTH_i = RSA_Sign(Initiator_Private_Key, Hash)
  4. 发送 AUTH_i  响应方

响应方验证 AUTH_i：
  1. 重新计算 InitiatorSignedOctets
  2. 计算哈希：Hash = SHA256(InitiatorSignedOctets)
  3. 使用发起方证书中的公钥验证：
     RSA_Verify(Initiator_Public_Key, Hash, AUTH_i) = TRUE/FALSE

响应方认证（生成 AUTH_r）：
  1. 计算 ResponderSignedOctets = RealMessage2 | Ni | prf(SK_pr, IDr')
  2. 使用 SHA256 计算哈希：Hash = SHA256(ResponderSignedOctets)
  3. 使用响应方私钥签名：AUTH_r = RSA_Sign(Responder_Private_Key, Hash)
  4. 发送 AUTH_r  发起方

发起方验证 AUTH_r：
  1. 重新计算 ResponderSignedOctets
  2. 计算哈希：Hash = SHA256(ResponderSignedOctets)
  3. 使用响应方证书中的公钥验证：
     RSA_Verify(Responder_Public_Key, Hash, AUTH_r) = TRUE/FALSE
```

**关键点**：

-  私钥用于签名，绝不传输
-  公钥用于验证，包含在证书中传输
-  双方互相验证对方的签名
-  使用 SK_pi/SK_pr 绑定到当前会话

#### **3.2.2 预共享密钥认证（PSK）**

| 密钥名称 | 密钥类型 | 所有者 | 用途 | 生成方 |
|---------|---------|-------|------|-------|
| Pre-Shared Key | 对称 | 双方预配置 | 生成 AUTH 载荷 | 双方 |

**认证流程**：

```
发起方生成 AUTH_i：
  AUTH_i = prf(prf(PSK, \"Key Pad for IKEv2\"), 
               <InitiatorSignedOctets>)

响应方验证 AUTH_i：
  重新计算 AUTH_i'，比较是否相等

响应方生成 AUTH_r：
  AUTH_r = prf(prf(PSK, \"Key Pad for IKEv2\"), 
               <ResponderSignedOctets>)

发起方验证 AUTH_r：
  重新计算 AUTH_r'，比较是否相等
```

### 3.3 CHILD_SA (ESP) 阶段密钥

#### **3.3.1 ESP 密钥材料**

| 密钥名称 | 密钥类型 | 长度 | 使用方向 | 加密方 | 解密方 | 用途 |
|---------|---------|-----|---------|-------|-------|------|
| ESP_SK_ei | 对称 | ENCR 密钥长度 | 发起方响应方 | 发起方 | 响应方 | 加密出站 ESP 数据包 |
| ESP_SK_er | 对称 | ENCR 密钥长度 | 响应方发起方 | 响应方 | 发起方 | 加密出站 ESP 数据包 |
| ESP_SK_ai | 对称 | INTEG 密钥长度 | 发起方响应方 | 发起方 | 响应方 | 认证出站 ESP 数据包 |
| ESP_SK_ar | 对称 | INTEG 密钥长度 | 响应方发起方 | 响应方 | 发起方 | 认证出站 ESP 数据包 |

**派生公式**：

```
KEYMAT = prf+ (SK_d, Ni | Nr)

{ESP_SK_ei | ESP_SK_ai | ESP_SK_er | ESP_SK_ar} = KEYMAT
```

**使用流程**：

```
发起方发送数据包（例如：10.1.0.1  10.2.0.1）：
  1. 使用 ESP_SK_ei 加密 IP 数据包
  2. 使用 ESP_SK_ai 计算 HMAC（认证）
  3. 封装成 ESP 数据包发送

响应方接收数据包：
  1. 使用 ESP_SK_ai 验证 HMAC
  2. 使用 ESP_SK_ei 解密 IP 数据包
  3. 转发给内部网络

响应方发送数据包（例如：10.2.0.1  10.1.0.1）：
  1. 使用 ESP_SK_er 加密 IP 数据包
  2. 使用 ESP_SK_ar 计算 HMAC（认证）
  3. 封装成 ESP 数据包发送

发起方接收数据包：
  1. 使用 ESP_SK_ar 验证 HMAC
  2. 使用 ESP_SK_er 解密 IP 数据包
  3. 转发给内部网络
```

**关键特性**：

-  双向独立密钥（发起方和响应方各自的加密/认证密钥）
-  对称加密（加密和解密使用相同的密钥，但方向不同）
-  防止重放攻击（每个方向独立的序列号）
-  密钥隔离（一个方向的密钥泄露不影响另一个方向）

### 3.4 密钥长度对照表

| 算法 | 密钥长度 | IV 长度 | HMAC 输出长度 |
|------|---------|--------|--------------|
| AES-128-CBC | 16 字节 (128 位) | 16 字节 | - |
| AES-256-CBC | 32 字节 (256 位) | 16 字节 | - |
| AES-128-GCM | 16 字节 (128 位) | 8 字节 | - (内置认证) |
| AES-256-GCM | 32 字节 (256 位) | 8 字节 | - (内置认证) |
| **SM4-CBC** | 16 字节 (128 位) | 16 字节 | - |
| **SM4-GCM** | 16 字节 (128 位) | 8 字节 | - (内置认证) |
| 3DES | 24 字节 (192 位) | 8 字节 | - |
| HMAC-SHA1-96 | - | - | 12 字节 (96 位) |
| HMAC-SHA256-128 | - | - | 16 字节 (128 位) |
| **HMAC-SM3** | - | - | 32 字节 (256 位) |
| PRF-HMAC-SHA256 | 动态 | - | 32 字节 (256 位) |
| **PRF-HMAC-SM3** | 动态 | - | 32 字节 (256 位) |

---

## 4. 密钥生命周期管理

### 4.1 密钥重协商（Rekeying）

| 密钥类型 | 默认生命周期 | 重协商触发条件 | 重协商方式 |
|---------|------------|--------------|-----------|
| IKE_SA 密钥 | 4 小时 | 时间到期或数据量 | CREATE_CHILD_SA (IKE Rekey) |
| CHILD_SA 密钥 | 1 小时 | 时间到期或数据量 | CREATE_CHILD_SA (ESP Rekey) |
| DH 密钥对 | 临时 | 每次 IKE_SA_INIT | 重新生成 |

**重协商流程**：

```
IKE_SA 重协商：
  1. 发起 CREATE_CHILD_SA 请求（带 DH 载荷）
  2. 交换新的 DH 公钥
  3. 生成新的 SKEYSEED 和 IKE 密钥
  4. 切换到新的 IKE_SA
  5. 删除旧的 IKE_SA

CHILD_SA 重协商：
  1. 发起 CREATE_CHILD_SA 请求（可选 DH 载荷 for PFS）
  2. 生成新的 ESP 密钥材料
  3. 安装新的 ESP SA
  4. 切换到新的 CHILD_SA
  5. 删除旧的 CHILD_SA
```

### 4.2 密钥销毁

| 密钥类型 | 销毁时机 | 销毁方式 |
|---------|---------|---------|
| DH 私钥 | 共享密钥生成后 | 内存清零 |
| SKEYSEED | IKE_SA 删除时 | 内存清零 |
| IKE_SA 密钥 | IKE_SA 删除时 | 内存清零 |
| CHILD_SA 密钥 | CHILD_SA 删除时 | 内核 SA 删除 |
| 证书私钥 | 永不销毁（持久化存储） | 文件系统保护 |

---

## 5. 国密算法支持

### 5.1 国密算法套件

| 协商阶段 | 国密算法组合 | 对应国际算法 |
|---------|------------|-------------|
| IKE Proposal | SM4-CBC + HMAC-SM3 + SM2 Curve | AES-CBC + HMAC-SHA256 + ECP-256 |
| IKE Proposal | SM4-GCM + PRF-HMAC-SM3 + SM2 Curve | AES-GCM + PRF-HMAC-SHA256 + ECP-256 |
| Authentication | SM2-SM3 | RSA-SHA256 / ECDSA-SHA256 |
| ESP Proposal | SM4-CBC + HMAC-SM3 | AES-CBC + HMAC-SHA256 |
| ESP Proposal | SM4-GCM | AES-GCM |

### 5.2 国密密钥特性

| 国密算法 | 密钥类型 | 密钥长度 | 对应国际算法 |
|---------|---------|---------|-------------|
| **SM2** | 非对称（ECC） | 256 位 | ECDSA P-256 |
| **SM3** | 哈希函数 | 256 位输出 | SHA-256 |
| **SM4** | 对称分组密码 | 128 位 | AES-128 |
| **HMAC-SM3** | 消息认证码 | 256 位输出 | HMAC-SHA256 |

**strongSwan 国密配置示例**：

```bash
# swanctl.conf - 完整国密配置
connections {
  gm-vpn {
    # IKE 提案：SM4-GCM 加密 + PRF-HMAC-SM3 + SM2 曲线 DH
    proposals = sm4gcm128-prfsm3-sm2p256v1
    
    local {
      auth = pubkey
      certs = initiator_sm2_cert.pem    # SM2 证书
      id = \"CN=Initiator\"
    }
    
    remote {
      auth = pubkey
      id = \"CN=Responder\"
    }
    
    children {
      tunnel {
        # ESP 提案：SM4-GCM 加密 + SM2 曲线 PFS
        esp_proposals = sm4gcm128-sm2p256v1
        
        local_ts = 10.1.0.0/16
        remote_ts = 10.2.0.0/16
      }
    }
  }
}
```

---

## 6. 完整流程示例

### 6.1 标准 IKEv2 + ESP (AES-GCM)

```
阶段 1: IKE_SA_INIT
  发起方  响应方: SAi1, KEi, Ni
    - SAi1: AES-256-GCM + PRF-HMAC-SHA256 + MODP-2048
    - KEi: DH 公钥 (Group 14)
    - Ni: 随机数
  
  响应方  发起方: SAr1, KEr, Nr
    - SAr1: 选择的提案
    - KEr: DH 公钥
    - Nr: 随机数
  
  双方计算:
    - DH 共享密钥: g^(DH_i_private * DH_r_private)
    - SKEYSEED = PRF-HMAC-SHA256(Ni | Nr, g^ir)
    - SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
  
  密钥使用:
    - SK_ei/SK_er: AES-256-GCM (对称加密，32 字节密钥)
    - SK_ai/SK_ar: 不需要（GCM 内置认证）
    - SK_pi/SK_pr: PRF-HMAC-SHA256 (对称，32 字节)

阶段 2: IKE_AUTH (加密传输)
  发起方  响应方: [IDi, CERT_i, AUTH_i, SAi2, TSi, TSr]
    - 使用 SK_ei 加密（AES-256-GCM）
    - AUTH_i = RSA_Sign(Initiator_Private_Key, SHA256(SignedOctets))
      * Initiator_Private_Key: RSA 私钥 (非对称，2048/4096 位)
    - SAi2: ESP 提案 (AES-256-GCM + MODP-2048 PFS)
  
  响应方验证:
    - 使用 SK_ei 解密
    - 使用 Initiator_Public_Key 验证 AUTH_i
      * RSA_Verify(Initiator_Public_Key, SHA256(SignedOctets), AUTH_i)
  
  响应方  发起方: [IDr, CERT_r, AUTH_r, SAr2, TSi, TSr]
    - 使用 SK_er 加密（AES-256-GCM）
    - AUTH_r = RSA_Sign(Responder_Private_Key, SHA256(SignedOctets))
      * Responder_Private_Key: RSA 私钥 (非对称，2048/4096 位)
  
  发起方验证:
    - 使用 SK_er 解密
    - 使用 Responder_Public_Key 验证 AUTH_r
  
  双方计算 ESP 密钥:
    - KEYMAT = PRF+(SK_d, Ni | Nr)
    - ESP_SK_ei, ESP_SK_ai, ESP_SK_er, ESP_SK_ar
  
  ESP 密钥特性:
    - ESP_SK_ei/ESP_SK_er: AES-256-GCM (对称，32 字节)
    - ESP_SK_ai/ESP_SK_ar: 不需要（GCM 内置认证）

阶段 3: ESP 数据传输
  发起方  响应方 (例如: 10.1.0.100  10.2.0.200)
    1. 封装: IP(10.1.0.100  10.2.0.200) + TCP/UDP Payload
    2. 加密: 使用 ESP_SK_ei (AES-256-GCM, 32 字节密钥)
       - 加密方: 发起方
       - 解密方: 响应方
    3. 封装 ESP: ESP Header + 加密数据 + ESP Trailer + ICV
    4. 外层 IP: IP(GW_i  GW_r) + ESP Packet
  
  响应方接收:
    1. 验证 ICV (GCM 内置认证)
    2. 解密: 使用 ESP_SK_ei (同一个密钥，对称解密)
    3. 解封装: 还原原始 IP 包
    4. 转发到内部网络 (10.2.0.200)
  
  响应方  发起方 (例如: 10.2.0.200  10.1.0.100)
    1. 封装: IP(10.2.0.200  10.1.0.100) + TCP/UDP Payload
    2. 加密: 使用 ESP_SK_er (AES-256-GCM, 32 字节密钥)
       - 加密方: 响应方
       - 解密方: 发起方
    3. 封装 ESP: ESP Header + 加密数据 + ESP Trailer + ICV
    4. 外层 IP: IP(GW_r  GW_i) + ESP Packet
  
  发起方接收:
    1. 验证 ICV (GCM 内置认证)
    2. 解密: 使用 ESP_SK_er (同一个密钥，对称解密)
    3. 解封装: 还原原始 IP 包
    4. 转发到内部网络 (10.1.0.100)
```

### 6.2 国密 IKEv2 + ESP (SM4-GCM)

```
阶段 1: IKE_SA_INIT
  发起方  响应方: SAi1, KEi, Ni
    - SAi1: SM4-GCM + PRF-HMAC-SM3 + SM2 Curve
    - KEi: SM2 DH 公钥 (256 位)
    - Ni: 随机数
  
  响应方  发起方: SAr1, KEr, Nr
  
  双方计算:
    - SM2 DH 共享密钥 (256 位)
    - SKEYSEED = PRF-HMAC-SM3(Ni | Nr, g^ir)
    - SK_d, SK_ei, SK_er, SK_pi, SK_pr (使用 PRF-HMAC-SM3 派生)
  
  密钥使用:
    - SK_ei/SK_er: SM4-GCM (对称加密，16 字节密钥)
    - SK_pi/SK_pr: PRF-HMAC-SM3 (对称，32 字节)

阶段 2: IKE_AUTH
  发起方  响应方: [IDi, CERT_i, AUTH_i, SAi2, TSi, TSr]
    - 使用 SK_ei 加密（SM4-GCM）
    - AUTH_i = SM2_Sign(Initiator_Private_Key, SM3(SignedOctets))
      * Initiator_Private_Key: SM2 私钥 (非对称，256 位)
    - SAi2: ESP 提案 (SM4-GCM + SM2 Curve PFS)
  
  响应方验证:
    - 使用 SK_ei 解密
    - 使用 Initiator_Public_Key 验证 AUTH_i
      * SM2_Verify(Initiator_Public_Key, SM3(SignedOctets), AUTH_i)
  
  响应方  发起方: [IDr, CERT_r, AUTH_r, SAr2, TSi, TSr]
    - 使用 SK_er 加密（SM4-GCM）
    - AUTH_r = SM2_Sign(Responder_Private_Key, SM3(SignedOctets))
  
  双方计算 ESP 密钥:
    - KEYMAT = PRF-HMAC-SM3(SK_d, Ni | Nr)
    - ESP_SK_ei, ESP_SK_er (SM4-GCM, 16 字节)

阶段 3: ESP 数据传输
  发起方  响应方:
    - 加密: 使用 ESP_SK_ei (SM4-GCM, 16 字节密钥)
      * 加密方: 发起方
      * 解密方: 响应方
  
  响应方  发起方:
    - 加密: 使用 ESP_SK_er (SM4-GCM, 16 字节密钥)
      * 加密方: 响应方
      * 解密方: 发起方
```

---

## 7. 密钥汇总表

### 7.1 所有密钥类型总览

| 序号 | 密钥名称 | 密钥类型 | 所有者 | 用途 | 加密方 | 解密方 | 生命周期 |
|-----|---------|---------|-------|------|-------|-------|---------|
| 1 | DH_i_private | 非对称（私钥） | 发起方 | DH 密钥交换 | - | - | 临时 |
| 2 | DH_i_public | 非对称（公钥） | 发起方 | DH 密钥交换 | - | - | 临时 |
| 3 | DH_r_private | 非对称（私钥） | 响应方 | DH 密钥交换 | - | - | 临时 |
| 4 | DH_r_public | 非对称（公钥） | 响应方 | DH 密钥交换 | - | - | 临时 |
| 5 | SKEYSEED | 对称 | 双方 | 根密钥种子 | - | - | IKE_SA 生命周期 |
| 6 | SK_d | 对称 | 双方 | 派生 CHILD_SA 密钥 | - | - | IKE_SA 生命周期 |
| 7 | SK_ai | 对称 | 双方 | IKE 消息认证 | 发起方 | 响应方 | IKE_SA 生命周期 |
| 8 | SK_ar | 对称 | 双方 | IKE 消息认证 | 响应方 | 发起方 | IKE_SA 生命周期 |
| 9 | SK_ei | 对称 | 双方 | IKE 消息加密 | 发起方 | 响应方 | IKE_SA 生命周期 |
| 10 | SK_er | 对称 | 双方 | IKE 消息加密 | 响应方 | 发起方 | IKE_SA 生命周期 |
| 11 | SK_pi | 对称 | 双方 | 发起方 AUTH 生成 | 发起方 | - | IKE_SA 生命周期 |
| 12 | SK_pr | 对称 | 双方 | 响应方 AUTH 生成 | 响应方 | - | IKE_SA 生命周期 |
| 13 | Initiator_Private_Key | 非对称（私钥） | 发起方 | 签名认证 | 发起方 | - | 持久 |
| 14 | Initiator_Public_Key | 非对称（公钥） | 发起方（证书） | 验证签名 | - | 响应方 | 持久 |
| 15 | Responder_Private_Key | 非对称（私钥） | 响应方 | 签名认证 | 响应方 | - | 持久 |
| 16 | Responder_Public_Key | 非对称（公钥） | 响应方（证书） | 验证签名 | - | 发起方 | 持久 |
| 17 | ESP_SK_ei | 对称 | 双方 | ESP 数据加密 | 发起方 | 响应方 | CHILD_SA 生命周期 |
| 18 | ESP_SK_er | 对称 | 双方 | ESP 数据加密 | 响应方 | 发起方 | CHILD_SA 生命周期 |
| 19 | ESP_SK_ai | 对称 | 双方 | ESP 数据认证 | 发起方 | 响应方 | CHILD_SA 生命周期 |
| 20 | ESP_SK_ar | 对称 | 双方 | ESP 数据认证 | 响应方 | 发起方 | CHILD_SA 生命周期 |
| 21 | Pre-Shared Key (可选) | 对称 | 双方 | PSK 认证 | 双方 | 双方 | 持久 |

### 7.2 对称密钥 vs 非对称密钥

| 分类 | 密钥数量 | 密钥列表 |
|-----|---------|---------|
| **非对称密钥** | 8 个（4 对） | DH_i_private/public, DH_r_private/public<br>Initiator_Private/Public_Key<br>Responder_Private/Public_Key |
| **对称密钥** | 13 个 | SKEYSEED, SK_d<br>SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr<br>ESP_SK_ei, ESP_SK_er, ESP_SK_ai, ESP_SK_ar<br>Pre-Shared Key (可选) |

---

## 8. 参考资料

- RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2)
- RFC 4303: IP Encapsulating Security Payload (ESP)
- RFC 5996: Internet Key Exchange Protocol Version 2 (IKEv2) - 已废弃
- GB/T 32918: SM2 椭圆曲线公钥密码算法
- GB/T 32905: SM3 密码杂凑算法
- GB/T 32907: SM4 分组密码算法
- strongSwan Documentation: https://docs.strongswan.org/

---

## 附录：strongSwan 代码位置

```c
// IKE 密钥派生
src/libcharon/sa/ikev2/keymat_v2.c:240 - derive_ike_keys()

// CHILD_SA (ESP) 密钥派生
src/libcharon/sa/ikev2/keymat_v2.c:540 - derive_child_keys()

// 公钥认证
src/libcharon/sa/ikev2/authenticators/pubkey_authenticator.c

// PSK 认证
src/libcharon/sa/ikev2/authenticators/psk_authenticator.c

// ESP 加密
src/libipsec/esp_packet.c:289 - encrypt()

// ESP 解密
src/libipsec/esp_packet.c:228 - decrypt()

// DH 密钥交换
src/libstrongswan/plugins/gmp/gmp_diffie_hellman.c
src/libstrongswan/plugins/openssl/openssl_diffie_hellman.c

// 国密算法实现（需要集成 GmSSL）
外部库: GmSSL 3.0+
集成位置: src/libstrongswan/plugins/gmssl/
```

---

**文档版本**: 1.0  
**最后更新**: 2025-10-29  
**适用版本**: strongSwan 5.9.x+  
**作者**: VPN 技术文档项目组
