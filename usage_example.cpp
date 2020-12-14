  #include <iostream>
  #include <iomanip>
  #include "hashing.h"

  using namespace std;

  int main()
  {
	  string test = "ala";

  	try
	  {
		  string test_SHA0   = hash_lib::SHA0(test);
		  string test_SHA1   = hash_lib::SHA1(test);
		  string test_SHA224 = hash_lib::SHA224(test);
		  string test_SHA256 = hash_lib::SHA256(test);
		  string test_SHA384 = hash_lib::SHA384(test);
		  string test_SHA512 = hash_lib::SHA512(test);
		  string test_MD5 	 = hash_lib::MD5(test);
		  string test_MD4    = hash_lib::MD4(test);

		  cout<<"--------------------------"<<endl<<endl;

		  cout<<" MD4: "<<test_MD4.substr(0,16)<<endl<<endl
		      	       <<"      "<<test_MD4.substr(16,16)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

	  	  cout<<" MD5: "<<test_MD5.substr(0,16)<<endl<<endl
		  	       <<"      "<<test_MD5.substr(16,16)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA0: "<<test_SHA0.substr(0,16)<<endl<<endl
		  	      <<"       "<<test_SHA0.substr(16,16)<<endl<<endl
			      <<"       "<<test_SHA0.substr(32,8)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA1: "<<test_SHA1.substr(0,16)<<endl<<endl
		  	      <<"       "<<test_SHA1.substr(16,16)<<endl<<endl
			      <<"       "<<test_SHA1.substr(32,8)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA-224: "<<test_SHA224.substr(0,16)<<endl<<endl
		  	      <<"          "<<test_SHA224.substr(16,16)<<endl<<endl
			      <<"          "<<test_SHA224.substr(32,16)<<endl<<endl
			      <<"          "<<test_SHA224.substr(48,8)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA-256: "<<test_SHA256.substr(0,16)<<endl<<endl
		  	      <<"          "<<test_SHA256.substr(16,16)<<endl<<endl
			      <<"          "<<test_SHA256.substr(32,16)<<endl<<endl
			      <<"          "<<test_SHA256.substr(48,16)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA-384: "<<test_SHA384.substr(0,16)<<endl<<endl
		  	      <<"          "<<test_SHA384.substr(16,16)<<endl<<endl
			      <<"          "<<test_SHA384.substr(32,16)<<endl<<endl
			      <<"          "<<test_SHA384.substr(48,16)<<endl<<endl
			      <<"          "<<test_SHA384.substr(64,16)<<endl<<endl
			      <<"          "<<test_SHA384.substr(80,16)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

		  cout<<" SHA-512: "<<test_SHA512.substr(0,16)<<endl<<endl
		  	      <<"          "<<test_SHA512.substr(16,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(32,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(48,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(64,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(80,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(96,16)<<endl<<endl
			      <<"          "<<test_SHA512.substr(112,16)<<endl<<endl;

          cout<<"--------------------------"<<endl<<endl;

	  }
	  catch(...)
	  {
		  cout<<"Something went wrong"<<endl;
	  }

	  return 0;
  }
