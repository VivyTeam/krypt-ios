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

public final class MD5: DigestType {
  static let blockSize: Int = 64
  static let digestLength: Int = 16 // 128 / 8
  fileprivate static let hashInitialValue: Array<UInt32> = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476]

  fileprivate var accumulated = Array<UInt8>()
  fileprivate var processedBytesTotalCount: Int = 0
  fileprivate var accumulatedHash: Array<UInt32> = MD5.hashInitialValue

  /** specifies the per-round shift amounts */
  private let s: Array<UInt32> = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]

  /** binary integer part of the sines of integers (Radians) */
  private let k: Array<UInt32> = [
    0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE,
    0xF57C_0FAF, 0x4787_C62A, 0xA830_4613, 0xFD46_9501,
    0x6980_98D8, 0x8B44_F7AF, 0xFFFF_5BB1, 0x895C_D7BE,
    0x6B90_1122, 0xFD98_7193, 0xA679_438E, 0x49B4_0821,
    0xF61E_2562, 0xC040_B340, 0x265E_5A51, 0xE9B6_C7AA,
    0xD62F_105D, 0x2441453, 0xD8A1_E681, 0xE7D3_FBC8,
    0x21E1_CDE6, 0xC337_07D6, 0xF4D5_0D87, 0x455A_14ED,
    0xA9E3_E905, 0xFCEF_A3F8, 0x676F_02D9, 0x8D2A_4C8A,
    0xFFFA_3942, 0x8771_F681, 0x6D9D_6122, 0xFDE5_380C,
    0xA4BE_EA44, 0x4BDE_CFA9, 0xF6BB_4B60, 0xBEBF_BC70,
    0x289B_7EC6, 0xEAA1_27FA, 0xD4EF_3085, 0x4881D05,
    0xD9D4_D039, 0xE6DB_99E5, 0x1FA2_7CF8, 0xC4AC_5665,
    0xF429_2244, 0x432A_FF97, 0xAB94_23A7, 0xFC93_A039,
    0x655B_59C3, 0x8F0C_CC92, 0xFFEF_F47D, 0x8584_5DD1,
    0x6FA8_7E4F, 0xFE2C_E6E0, 0xA301_4314, 0x4E08_11A1,
    0xF753_7E82, 0xBD3A_F235, 0x2AD7_D2BB, 0xEB86_D391
  ]

  public init() {}

  public func calculate(for bytes: Array<UInt8>) -> Array<UInt8> {
    do {
      return try update(withBytes: bytes.slice, isLast: true)
    } catch {
      fatalError()
    }
  }

  // mutating currentHash in place is way faster than returning new result
  fileprivate func process(block chunk: ArraySlice<UInt8>, currentHash: inout Array<UInt32>) {
    assert(chunk.count == 16 * 4)

    // Initialize hash value for this chunk:
    var A: UInt32 = currentHash[0]
    var B: UInt32 = currentHash[1]
    var C: UInt32 = currentHash[2]
    var D: UInt32 = currentHash[3]

    var dTemp: UInt32 = 0

    // Main loop
    for j in 0 ..< k.count {
      var g = 0
      var F: UInt32 = 0

      switch j {
      case 0 ... 15:
        F = (B & C) | ((~B) & D)
        g = j
        break
      case 16 ... 31:
        F = (D & B) | (~D & C)
        g = (5 * j + 1) % 16
        break
      case 32 ... 47:
        F = B ^ C ^ D
        g = (3 * j + 5) % 16
        break
      case 48 ... 63:
        F = C ^ (B | (~D))
        g = (7 * j) % 16
        break
      default:
        break
      }
      dTemp = D
      D = C
      C = B

      // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15 and get M[g] value
      let gAdvanced = g << 2

      var Mg = UInt32(chunk[chunk.startIndex &+ gAdvanced])
      Mg |= UInt32(chunk[chunk.startIndex &+ gAdvanced &+ 1]) << 8
      Mg |= UInt32(chunk[chunk.startIndex &+ gAdvanced &+ 2]) << 16
      Mg |= UInt32(chunk[chunk.startIndex &+ gAdvanced &+ 3]) << 24

      B = B &+ rotateLeft(A &+ F &+ k[j] &+ Mg, by: s[j])
      A = dTemp
    }

    currentHash[0] = currentHash[0] &+ A
    currentHash[1] = currentHash[1] &+ B
    currentHash[2] = currentHash[2] &+ C
    currentHash[3] = currentHash[3] &+ D
  }
}

extension MD5: Updatable {
  public func update(withBytes bytes: ArraySlice<UInt8>, isLast: Bool = false) throws -> Array<UInt8> {
    accumulated += bytes

    if isLast {
      let lengthInBits = (processedBytesTotalCount + accumulated.count) * 8
      let lengthBytes = lengthInBits.bytes(totalBytes: 64 / 8) // A 64-bit representation of b

      // Step 1. Append padding
      bitPadding(to: &accumulated, blockSize: MD5.blockSize, allowance: 64 / 8)

      // Step 2. Append Length a 64-bit representation of lengthInBits
      accumulated += lengthBytes.reversed()
    }

    var processedBytes = 0
    for chunk in accumulated.batched(by: MD5.blockSize) {
      if isLast || (accumulated.count - processedBytes) >= MD5.blockSize {
        process(block: chunk, currentHash: &accumulatedHash)
        processedBytes += chunk.count
      }
    }
    accumulated.removeFirst(processedBytes)
    processedBytesTotalCount += processedBytes

    // output current hash
    var result = Array<UInt8>()
    result.reserveCapacity(MD5.digestLength)

    for hElement in accumulatedHash {
      let hLE = hElement.littleEndian
      result += Array<UInt8>(arrayLiteral: UInt8(hLE & 0xFF), UInt8((hLE >> 8) & 0xFF), UInt8((hLE >> 16) & 0xFF), UInt8((hLE >> 24) & 0xFF))
    }

    // reset hash value for instance
    if isLast {
      accumulatedHash = MD5.hashInitialValue
    }

    return result
  }
}
