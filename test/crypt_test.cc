/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <gcrypt.h>
#include <sstream>

#include "contrib/gtest/include/gtest/gtest.h"
#include "src/crypt.h"
#include "src/logger.h"

using namespace np1sec;
/*
const unsigned char SESSION_KEY[] = {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
  0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

const unsigned char SESSION_IV[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f
};
*/


/**
 * Extend the SecureString class to expose the wipe_securely method.
 */
class SecureStringT : public SecureString
{
  public:
  SecureStringT(const char* dat, size_t len) : SecureString(dat, len) { };
  SecureStringT(const uint8_t* dat, size_t len) : SecureString(dat, len) { };

  void wipe_securely() {
    SecureString::wipe_securely();
  }
};


class CryptTest : public ::testing::Test { };
class SecureStringTest : public ::testing::Test { };

TEST_F(CryptTest, test_hash) {
  logger.silly("CryptTest/test_hash");
  std::string str = "abc";
  std::string exp =
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad";
  uint8_t *res = new HashBlock;
  gcry_error_t err = hash(reinterpret_cast<const void *>(str.c_str()),
                          3, res, false);
  EXPECT_FALSE(err);
  std::stringstream buf;
  buf << std::hex << std::internal << std::setfill('0');
  for (size_t i = 0; i < c_hash_length; i++) {
    buf << std::setw(2) << static_cast<uint>(res[i]);
  }
  ASSERT_EQ(exp, buf.str());
  delete[] res;
}

TEST_F(CryptTest, test_encrypt_decrypt) {
  logger.silly("CryptTest/test_encrypt_decrypt");
  Cryptic cryptic;
  std::string test_text = "This is a string to be encrypted";
  cryptic.init(); // HURRY
  std::string enc_text = cryptic.Encrypt(test_text.c_str());
  std::string dec_text = cryptic.Decrypt(enc_text);
  ASSERT_STREQ(test_text.c_str(), dec_text.c_str());
}


TEST_F(CryptTest, test_sign_verify) {
  logger.silly("CryptTest/test_sign_verify");
  Cryptic cryptic;
  std::string test_text = "This is a string to be encrypted";
  unsigned char *sigbuf = NULL;
  size_t siglen;
  unsigned int no_trial = 10;
  cryptic.init();
  for(unsigned int i = 0; i <no_trial; i++) {
    test_text = "This is a string to be encrypted" + std::to_string(i);
    ASSERT_NO_THROW(cryptic.sign(&sigbuf, &siglen, test_text));
    ASSERT_TRUE(cryptic.verify(test_text, sigbuf, cryptic.get_ephemeral_pub_key()));
    delete[] sigbuf;
    sigbuf = NULL;
  }
}

TEST_F(CryptTest, test_teddh_test) {
  logger.silly("CryptTest/test_teddh_test");

  AsymmetricKeyPair alice_keys = generate_key_pair();
  AsymmetricKeyPair bob_keys = generate_key_pair();
  
  ASSERT_TRUE(alice_keys.public_key.unwrap() != nullptr);
  ASSERT_TRUE(alice_keys.private_key.unwrap() != nullptr);
  ASSERT_TRUE(bob_keys.public_key.unwrap() != nullptr);
  ASSERT_TRUE(bob_keys.private_key.unwrap() != nullptr);
 
  Cryptic alice_crypt, bob_crypt;
  alice_crypt.init(); //This is either stupid or have stupid name
  bob_crypt.init();

  //suppose we are first without lost of generality
  bool alice_is_first = true;
  bool bob_is_first = !alice_is_first;
  HashBlock teddh_alice_bob, teddh_bob_alice;
//Alice is making the tdh token, peer is bob
  ASSERT_NO_THROW(
    alice_crypt.triple_ed_dh(
      bob_crypt.get_ephemeral_pub_key(),
      bob_keys.public_key,
      alice_keys,
      bob_is_first,
      &teddh_alice_bob));
  //Bob is making the tdh token, peer is alice
  ASSERT_NO_THROW(
    bob_crypt.triple_ed_dh(
      alice_crypt.get_ephemeral_pub_key(),
      alice_keys.public_key,
      bob_keys,
      alice_is_first,
      &teddh_bob_alice));

  for(unsigned int i = 0; i < sizeof(HashBlock); i++) {
    ASSERT_EQ(teddh_alice_bob[i], teddh_bob_alice[i]);
  }
}

/**
 * Test that creating a secure string from an array of characters
 * with values all >= 0 will succeed.
 */
TEST_F(SecureStringTest, test_char_ptr_constructor_pass)
{
  logger.silly("CryptTest/test_chat_ptr_constructor_pass");
  char* str = new char[4];
  str[0] = 100; str[1] = 105;
  str[2] = 0; str[3] = 106;
  SecureStringT sstr(str, static_cast<size_t>(4));
  ASSERT_TRUE(sstr.length() == 4);
  delete[] str;
  const uint8_t* data = sstr.unwrap();
  ASSERT_TRUE(data[0] == 100);
  ASSERT_TRUE(data[1] == 105);
  ASSERT_TRUE(data[2] == 0);
  ASSERT_TRUE(data[3] == 106);
}

/**
 * Test that creating a secure string from an array of characters
 * containing a byte < 0 will lead to an exception.
 */
TEST_F(SecureStringTest, test_char_ptr_constructor_fail)
{
  logger.silly("CryptTest/test_chat_ptr_constructor_fail");
  char* str = new char[4];
  str[0] = 134; str[1] = 0;
  str[2] = -10; str[3] = 10;
  bool exception_encountered = false;
  try {
    SecureStringT sstr(str, static_cast<size_t>(4));
  } catch (SecureStringException& e) {
    exception_encountered = true;
  }
  delete[] str;
  ASSERT_TRUE(exception_encountered);
}

/**
 * Test that data is properly copied from the source array.
 */
TEST_F(SecureStringTest, test_uint8_t_ptr_constructor)
{
  logger.silly("CryptTest/test_uint8_t_ptr_constructor");
  uint8_t* bytes = new uint8_t[4];
  bytes[0] = 98; bytes[1] = 123;
  bytes[2] = 0; bytes[3] = 255;
  SecureStringT sstr(bytes, static_cast<size_t>(4));
  ASSERT_TRUE(sstr.length() == 4);
  delete[] bytes;
  const uint8_t* data = sstr.unwrap();
  ASSERT_TRUE(data[0] == 98);
  ASSERT_TRUE(data[1] == 123);
  ASSERT_TRUE(data[2] == 0);
  ASSERT_TRUE(data[3] == 255);
}

/**
 * Test that a call to wipe_securely does indeed clear the data.
 */
TEST_F(SecureStringTest, test_data_zeroing)
{
  logger.silly("CryptTest/test_data_zeroing");
  uint8_t bytes[4] = {100, 0, 123, 255};
  SecureStringT sstr(bytes, static_cast<size_t>(4));
  sstr.wipe_securely();
  const uint8_t* data = sstr.unwrap();
  for (unsigned int i = 0; i < 4; i++) {
    ASSERT_TRUE(data[i] == 0);
  }
}
