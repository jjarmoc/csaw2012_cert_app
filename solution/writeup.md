I'm finally getting around to writing up my solution to my own challenge in hopes that someone might find it interesting, and maybe learn something from it.

I'm adding three files, all in the /solution/ subdirectory of the project.

Solver.rb - This is the meat of the update.  It's the exploit I wrote for my own challenge.  I didn't end up using this during the challenge, but it's always helpful to have an exploit if you need to test your own app. During development, this was the final step in ensuring the app was exploitable in the way I intended; kind of a reverse unit test :)

Maintanence.rb - This script ran hourly during the CTF.  It verifies the admin keypair works as intended, and the flag is present with the expected value.  Mostly this was to ensure the challenge was running as expected during the contest.  Also, it removes accounts that have been inactive for more than an hour.  This was just to keep the directory from growing larger as folks generated large numbers of certs while attacking.

Writeup.txt - that's this file.  I'm going to try to explain the vulnerability, how the exploit works, and how this sort of issue might appear in the file.  

## The Vuln
So, where's the vuln?

Well, if you look at the code and play with the app, you should quickly see that it allows users to create client certificates which they can then use to authenticate.  I did my best to ensure that input we take from the user is handled safely, and I don't believe there's any traditional web vulns in this app (though I'd love to hear from anyone who finds any!)

Without web vulns, we're left with the crypto bits.  It seems like there's a good deal of code around that functionality, doesn't it?

Digging around a bit, we see that the default route (which loads the index page) is as follows;
```ruby
    get '/' do
    	if (@authenticated == false)	
     		haml :noauth
    	elsif (@user.name == "admin")
    		haml :theflag
    	else
      		haml :index 
        end
    end
```

So there's three cases.  An unauth'd user sees the :noauth page (this corresponds to /views/noauth.haml). If a user is auth'd and their name is "admin", the see theflag.haml.  Otherwise (they're auth'd, but not admin) they see index.haml.  So in essence; auth as admin and we'll see the flag.

So, how does auth occur?  There's a helper that's called before each route is invoked that handles it.

```ruby
before do
  @client_cert = request.env['SSL_CLIENT_CERT'] ? request.env['SSL_CLIENT_CERT'] : nil
  @user = User.find_by_cert(@client_cert) ? User.find_by_cert(@client_cert) : nil	
  if (@user == nil)
    @authenticated = false
    @user = User.new("NONE", "NONE", "NONE", "NONE", "NONE")
  end
  @user.accessed()
end
```

Here we're grabbing any provided client certificate from the rack environment, and assigning it to @client_cert.  If there's no cert, this is nil.  We then search for this cert (the entire cert, not just a CN, etc.) in our User's DB and assign the return value to @user (nil if no user)  From there we check if there's a user.  If not, we set @authenticated to false and set @user to a dummy user object.  Otherwise, we just call the .accessed() method on the user in question (which simply updates their last accessed time in the DB)

After all that, we're left with @user being set to either a user object, or a dummy user object if they didn't provide a cert or provided an invalid cert.  The check for @user.name in the authorization checks on the index route just checks the name of the user as it exists in the object (which is populated by the DB).

Now, if you look at how certificates and user database entries are created (in the post '/cert/generate' route which I'm not going to go into much depth here) you'll see that 'admin' cannot appear anywhere in a user-supplied name.  I *think* the code is safe without this, as things like "admin%00" are not directly equal "admin", etc.  There are some error conditions along these lines, but I don't think any are exploitable (that is, they don't satisfy the string equality check for "admin").

So if we can't control the name of generated users in an exploitable fashion, what can we do?  One might think of SQLi to steal admin's private key from the database, but if you look at how User info is stored, you'll see that the private key isn't retained on the server side, and thus can't be stolen this way.

This leaves the crypto as our sole (hopefully) vuln.  Let's look at how certs are generated.

Again in the /cert/generate route, we see that after a few sanity checks (username is specified, and there's not an existing user with this name, etc.) we end up with the following call
```ruby
	user = User.generate(params[:name], params[:pw])
```

In /lib/User.rb, we see the code for the User.generate function
```ruby
	def self.generate(name = "", pw = nil)
		@@db = Connection.new.db('CertStore').collection('Users')
		@@ca = CA.new()
		user = self.new(name, Time.now, nil, nil, nil)
		user.genkeys(pw)
		return user
	end
```
This is fairly straightforward.  We create a user and then call user.genkeys passing along the password to use in protecting the .p12.  

user.genkeys writes the user to the db, and creates a .p12 keypair signed by ca.genp12.  It then extracts the public key and writes it to the database.
```ruby
	def genkeys(pw = nil)
		@@db = Connection.new.db('CertStore').collection('Users')
		new_user = { :name => @name, :created_on => @created, :last_access => @created}
		@user_id = @@db.insert(new_user)
		@p12 = @@ca.genp12(@name, @user_id.to_s, pw)
		@cert = @p12.certificate.to_s
		@@db.update( { :_id => @user_id }, '$set' => { :pubkey => @cert} )
	end
```
The user's p12 is stored only for the duration of that initial session, and returned to the requesting user.

Everything looks good so far, but let's dig a little more into the keypair generation.  Ca#genp12 is defined in Ca.rb.  Most of this function just assigned the certificate and key values to their corresponding objects, but near the start we see these two lines;
```ruby
  p = OpenSSL::BN.new(Prime.new(rand(PRIMES)).value)
  newkey = OpenSSL::PKey::RSA.new_from_pq(p)
```
What's with the rand() call?  Seeing calls to rand() in a crypto context is concerning; this isn't a cryptographically secure PRNG after all.  It's also taking a constant value 'PRIMES' as a paramater, which is set to '20' earlier in the code, so this is essentially rand(20).  This random value is then sent to Prime.new() and the return value is used for 'p' which is one of the RSA primes.

Looking into the Prime class a bit, it's purpose becomes clear.  It's a very small class, all it contains is this;
```ruby
require 'openssl'
require 'mongo'
include Mongo

class Prime
	attr_reader :id, :value

	def initialize(id)
		@id = id
		@@db = Connection.new.db('CertStore').collection('Primes')
		result = @@db.find( :id => id).first
		if (result) 
			@value = result["value"]
		end

		unless (@value)
			@value = String(OpenSSL::BN.generate_prime(1024))
			@@db.insert({:id => @id, :value => @value})
		end
	end
end
```

So when a prime is initialized, the argument to the constructor is an ID.  This ID is used to query a database and if there's a result, the corresponding value is returned.  If there's no such ID, we create a 1024 bit prime from OpenSSL::BN.generate_prime(1024), store this in the DB corredponding to this ID, and return it.

Essentially, this class just caches primes in a DB.  Given that (back in Ca.rb) we're calling rand(20) this class will return a prime, with a 1 in 20 chance of returning one that's already been returned before.

And there's the vuln.

## RSA Basics

What?  How is that a vulnerability?

If you're not familiar with the RSA algorithm, it essentially boils down to the function;
n = p*q

p and q are large prime numbers, and n is their product.  N becomes the basis of the public key, which is shared freely, and p and q (it's prime factors) form the basis of the private key, which needs to remain secret.  There's a bit more to it (I'm not mentioning d and e here), but that's a simplified overview.  For our purposes, it's enough to know that if you have both p and q, you can re-create the private key.

The security of RSA stems from the difficulty of factoring large prime numbers (again, this is simplified.  There's a concept known as the 'RSA problem' which is really the basis of it's strength, and is thought to be as hard as factoring).  Anyone who knows p and q can multiply them to determine the value of n, but the reverse is very hard.  Advances in factoring have led to some attacks against smaller primes, but the 2048 bit values of n used in this code are generally considered secure against factoring attacks today.

So, if factoring is out, where do we go?

## Shared Primes
Recall that we have a 1 in 20 shot at getting the same prime value of p for our keys due to the was that Prime class caches.  This means that a lot of keys are going to share primes.  Factoring keys is hard, but if we have duplicates there's another attack that comes in to play.  It's known as the 'shared factors attack.'

Calculating p and q given n is hard, but if we have two values (n1 and n2) such that p1=p2, we can easily determine the value of p, as well as q1 and q2.  Since semi-prime numbers (like n1 and n2) each have only two prime factors, we know that any shared divisor is going to be a factor of both.  This shared factor can be quickly determined by checking the greatest common denominator of n1 and n2; gcd(n1, n2) = p1 = p2.  There's lots of ways to do this, but one of the best known is the Euclidean algorithm (http://en.wikipedia.org/wiki/Euclidean_algorithm)  Once we have the shared factor p, we can divide to find the other factor that isn't shared.  So; q1 = n1/p and q2 = n2/p.

There's a really awesome explanation of this attack online at http://www.loyalty.org/~schoen/rsa/ so I'm not going to attempt to explain it again.  If the math interests you, check that out.

## The exploit

So with that in mind, our exploit (in /solution/Solver.rb) simply creates an account for our use, then logs in and fetches the public key of our victim user (admin in this scenario).  We then repeatedly generate keys, and check for a common factor between them and the admin cert's n value.  If we have a common factor, we call it p and calculate admin's q (q = n/p).  We then have everything we need to build admin's private key.

OpenSSL doesn't include the ability to create a key from p and q.  But recall that our server also needed to do this (as it wasn't calculating these values on every key generation).  The server code that allows for this is in /lib/openssl-patch.rb.  We can reuse that patch in our exploit as well, or calculate all the values ourselves if we're so inclined.

There are a few other ways to do this, but they're fundamentally not much different.  Instead of gcd(admin_n1, test_n2) we could have just tried dividing admin's n by our two factors (and if it divides evenly, we've recovered the first factor).  Alternately, we could do the whole challenge by using already existing public keys (created by other teams perhaps) which are available in the directory.  gcd() works there too.  However you slice it, the first step is to recover the shared key, then divide to calculate the other, and then build a private key for admin which we use to log in.

Once we log in with our recover private key for admin, we've got the flag.  For CSAW the flag was 
```
key{BeSureToMindYourPsAndQs}
```

## Real World
If this example seems a bit contrived, it's because it is.  It's highly unusual to cache values of one of our primes, and constrain their possibilities so tightly.  I suppose there'a a chance a well-meaning developer could do something like this in a misguided attempt at making key generation faster, but it's probably not too likely.  Anyone with any business working on key generation at this level should be aware that re-using primes is a bad idea.  Still, stranger things have happened.

What I really intended in this example was for it to be a simplified version of what might occur when a system lacks enough entropy to generate sufficiently random primes.  Such a system probably still wouldn't have a 1 in 20 reuse affinity like we see here, but that makes it much easier to attack our system in a reasonable time (a 1 in a million reuse would mean generating far more keys to find a shared factor).  

Not long ago, an interesting paper was released that showed such low-entropy key generation is occuring in practice.  (See 'Ron was wrong, Whit is right' http://eprint.iacr.org/2012/064.pdf) It's that paper that made me think this might be a fun CTF challenge, though this sort of problem has been known for far longer.

This is potential a problem for embedded systems which can't use common sources of entropy (disk, keyboard and mouse input, etc) and may frequently generate keys on their first boot.  Recent reports have claimed this is a a problem in some Cisco gear (http://packetstormsecurity.com/files/119363/Cisco-RV120W-RV220W-Weak-RSA-Key-Generation.html) which fits the model of a system where'd I'd expect key generation to be more difficult.

## That's it!
I hope you enjoyed this writeup, the challenge, and hopefully learned something.  Feel free to get in touch with me on twitter (@jjarmoc) if you feel so inclined.
