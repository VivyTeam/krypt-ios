//
//  CryptoSwift
//
//  Copyright (C) 2014-2017 Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.
//

//  TODO: generic for process32/64 (UInt32/UInt64)
//

public final class SHA2: DigestType {
  let variant: Variant
  let size: Int
  let blockSize: Int
  let digestLength: Int
  private let k: Array<UInt64>

  fileprivate var accumulated = Array<UInt8>()
  fileprivate var processedBytesTotalCount: Int = 0
  fileprivate var accumulatedHash32 = Array<UInt32>()
  fileprivate var accumulatedHash64 = Array<UInt64>()

  public enum Variant: RawRepresentable {
    case sha224, sha256, sha384, sha512

    public var digestLength: Int {
      return rawValue / 8
    }

    public var blockSize: Int {
      switch self {
      case .sha224, .sha256:
        return 64
      case .sha384, .sha512:
        return 128
      }
    }

    public typealias RawValue = Int
    public var rawValue: RawValue {
      switch self {
      case .sha224:
        return 224
      case .sha256:
        return 256
      case .sha384:
        return 384
      case .sha512:
        return 512
      }
    }

    public init?(rawValue: RawValue) {
      switch rawValue {
      case 224:
        self = .sha224
        break
      case 256:
        self = .sha256
        break
      case 384:
        self = .sha384
        break
      case 512:
        self = .sha512
        break
      default:
        return nil
      }
    }

    fileprivate var h: Array<UInt64> {
      switch self {
      case .sha224:
        return [0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939, 0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4]
      case .sha256:
        return [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19]
      case .sha384:
        return [0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939, 0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4]
      case .sha512:
        return [0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1, 0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179]
      }
    }

    fileprivate var finalLength: Int {
      switch self {
      case .sha224:
        return 7
      case .sha384:
        return 6
      default:
        return Int.max
      }
    }
  }

  public init(variant: SHA2.Variant) {
    self.variant = variant
    switch self.variant {
    case .sha224, .sha256:
      accumulatedHash32 = variant.h.map { UInt32($0) } // FIXME: UInt64 for process64
      blockSize = variant.blockSize
      size = variant.rawValue
      digestLength = variant.digestLength
      k = [
        0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
        0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
        0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
        0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
        0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
        0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
        0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
        0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2
      ]
    case .sha384, .sha512:
      accumulatedHash64 = variant.h
      blockSize = variant.blockSize
      size = variant.rawValue
      digestLength = variant.digestLength
      k = [
        0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC, 0x3956_C25B_F348_B538,
        0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118, 0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE,
        0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2, 0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235,
        0xC19B_F174_CF69_2694, 0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
        0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5, 0x983E_5152_EE66_DFAB,
        0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4, 0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725,
        0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70, 0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED,
        0x5338_0D13_9D95_B3DF, 0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
        0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30, 0xD192_E819_D6EF_5218,
        0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8, 0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53,
        0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8, 0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373,
        0x682E_6FF3_D6B2_B8A3, 0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
        0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B, 0xCA27_3ECE_EA26_619C,
        0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178, 0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6,
        0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B, 0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC,
        0x431D_67C4_9C10_0D4C, 0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817
      ]
    }
  }

  public func calculate(for bytes: Array<UInt8>) -> Array<UInt8> {
    do {
      return try update(withBytes: bytes.slice, isLast: true)
    } catch {
      return []
    }
  }

  fileprivate func process64(block chunk: ArraySlice<UInt8>, currentHash hh: inout Array<UInt64>) {
    // break chunk into sixteen 64-bit words M[j], 0 ≤ j ≤ 15, big-endian
    // Extend the sixteen 64-bit words into eighty 64-bit words:
    let M = UnsafeMutablePointer<UInt64>.allocate(capacity: k.count)
    M.initialize(repeating: 0, count: k.count)
    defer {
      M.deinitialize(count: self.k.count)
      M.deallocate()
    }
    for x in 0 ..< k.count {
      switch x {
      case 0 ... 15:
        let start = chunk.startIndex.advanced(by: x * 8) // * MemoryLayout<UInt64>.size
        M[x] = UInt64(bytes: chunk, fromIndex: start)
        break
      default:
        let s0 = rotateRight(M[x - 15], by: 1) ^ rotateRight(M[x - 15], by: 8) ^ (M[x - 15] >> 7)
        let s1 = rotateRight(M[x - 2], by: 19) ^ rotateRight(M[x - 2], by: 61) ^ (M[x - 2] >> 6)
        M[x] = M[x - 16] &+ s0 &+ M[x - 7] &+ s1
        break
      }
    }

    var A = hh[0]
    var B = hh[1]
    var C = hh[2]
    var D = hh[3]
    var E = hh[4]
    var F = hh[5]
    var G = hh[6]
    var H = hh[7]

    // Main loop
    for j in 0 ..< k.count {
      let s0 = rotateRight(A, by: 28) ^ rotateRight(A, by: 34) ^ rotateRight(A, by: 39)
      let maj = (A & B) ^ (A & C) ^ (B & C)
      let t2 = s0 &+ maj
      let s1 = rotateRight(E, by: 14) ^ rotateRight(E, by: 18) ^ rotateRight(E, by: 41)
      let ch = (E & F) ^ ((~E) & G)
      let t1 = H &+ s1 &+ ch &+ k[j] &+ UInt64(M[j])

      H = G
      G = F
      F = E
      E = D &+ t1
      D = C
      C = B
      B = A
      A = t1 &+ t2
    }

    hh[0] = (hh[0] &+ A)
    hh[1] = (hh[1] &+ B)
    hh[2] = (hh[2] &+ C)
    hh[3] = (hh[3] &+ D)
    hh[4] = (hh[4] &+ E)
    hh[5] = (hh[5] &+ F)
    hh[6] = (hh[6] &+ G)
    hh[7] = (hh[7] &+ H)
  }

  // mutating currentHash in place is way faster than returning new result
  fileprivate func process32(block chunk: ArraySlice<UInt8>, currentHash hh: inout Array<UInt32>) {
    // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15, big-endian
    // Extend the sixteen 32-bit words into sixty-four 32-bit words:
    let M = UnsafeMutablePointer<UInt32>.allocate(capacity: k.count)
    M.initialize(repeating: 0, count: k.count)
    defer {
      M.deinitialize(count: self.k.count)
      M.deallocate()
    }

    for x in 0 ..< k.count {
      switch x {
      case 0 ... 15:
        let start = chunk.startIndex.advanced(by: x * 4) // * MemoryLayout<UInt32>.size
        M[x] = UInt32(bytes: chunk, fromIndex: start)
        break
      default:
        let s0 = rotateRight(M[x - 15], by: 7) ^ rotateRight(M[x - 15], by: 18) ^ (M[x - 15] >> 3)
        let s1 = rotateRight(M[x - 2], by: 17) ^ rotateRight(M[x - 2], by: 19) ^ (M[x - 2] >> 10)
        M[x] = M[x - 16] &+ s0 &+ M[x - 7] &+ s1
        break
      }
    }

    var A = hh[0]
    var B = hh[1]
    var C = hh[2]
    var D = hh[3]
    var E = hh[4]
    var F = hh[5]
    var G = hh[6]
    var H = hh[7]

    // Main loop
    for j in 0 ..< k.count {
      let s0 = rotateRight(A, by: 2) ^ rotateRight(A, by: 13) ^ rotateRight(A, by: 22)
      let maj = (A & B) ^ (A & C) ^ (B & C)
      let t2 = s0 &+ maj
      let s1 = rotateRight(E, by: 6) ^ rotateRight(E, by: 11) ^ rotateRight(E, by: 25)
      let ch = (E & F) ^ ((~E) & G)
      let t1 = H &+ s1 &+ ch &+ UInt32(k[j]) &+ M[j]

      H = G
      G = F
      F = E
      E = D &+ t1
      D = C
      C = B
      B = A
      A = t1 &+ t2
    }

    hh[0] = hh[0] &+ A
    hh[1] = hh[1] &+ B
    hh[2] = hh[2] &+ C
    hh[3] = hh[3] &+ D
    hh[4] = hh[4] &+ E
    hh[5] = hh[5] &+ F
    hh[6] = hh[6] &+ G
    hh[7] = hh[7] &+ H
  }
}

extension SHA2: Updatable {
  public func update(withBytes bytes: ArraySlice<UInt8>, isLast: Bool = false) throws -> Array<UInt8> {
    accumulated += bytes

    if isLast {
      let lengthInBits = (processedBytesTotalCount + accumulated.count) * 8
      let lengthBytes = lengthInBits.bytes(totalBytes: blockSize / 8) // A 64-bit/128-bit representation of b. blockSize fit by accident.

      // Step 1. Append padding
      bitPadding(to: &accumulated, blockSize: blockSize, allowance: blockSize / 8)

      // Step 2. Append Length a 64-bit representation of lengthInBits
      accumulated += lengthBytes
    }

    var processedBytes = 0
    for chunk in accumulated.batched(by: blockSize) {
      if isLast || (accumulated.count - processedBytes) >= blockSize {
        switch variant {
        case .sha224, .sha256:
          process32(block: chunk, currentHash: &accumulatedHash32)
        case .sha384, .sha512:
          process64(block: chunk, currentHash: &accumulatedHash64)
        }
        processedBytes += chunk.count
      }
    }
    accumulated.removeFirst(processedBytes)
    processedBytesTotalCount += processedBytes

    // output current hash
    var result = Array<UInt8>(repeating: 0, count: variant.digestLength)
    switch variant {
    case .sha224, .sha256:
      var pos = 0
      for idx in 0 ..< accumulatedHash32.count where idx < variant.finalLength {
        let h = accumulatedHash32[idx]
        result[pos + 0] = UInt8((h >> 24) & 0xFF)
        result[pos + 1] = UInt8((h >> 16) & 0xFF)
        result[pos + 2] = UInt8((h >> 8) & 0xFF)
        result[pos + 3] = UInt8(h & 0xFF)
        pos += 4
      }
    case .sha384, .sha512:
      var pos = 0
      for idx in 0 ..< accumulatedHash64.count where idx < variant.finalLength {
        let h = accumulatedHash64[idx]
        result[pos + 0] = UInt8((h >> 56) & 0xFF)
        result[pos + 1] = UInt8((h >> 48) & 0xFF)
        result[pos + 2] = UInt8((h >> 40) & 0xFF)
        result[pos + 3] = UInt8((h >> 32) & 0xFF)
        result[pos + 4] = UInt8((h >> 24) & 0xFF)
        result[pos + 5] = UInt8((h >> 16) & 0xFF)
        result[pos + 6] = UInt8((h >> 8) & 0xFF)
        result[pos + 7] = UInt8(h & 0xFF)
        pos += 8
      }
    }

    // reset hash value for instance
    if isLast {
      switch variant {
      case .sha224, .sha256:
        accumulatedHash32 = variant.h.lazy.map { UInt32($0) } // FIXME: UInt64 for process64
      case .sha384, .sha512:
        accumulatedHash64 = variant.h
      }
    }

    return result
  }
}
