#include <NTL/ZZ.h>
#include <time.h>
#include <stdlib.h>
#include <fstream.h>
 
NTL_CLIENT


ZZ zzcat(ZZ a,ZZ b)
{
    ZZ i,bb;
	i=0;
	bb=b;
	while(1)
	{
	  i++;
      b=b/10;
	  if(b==0)
		break;
	}
   
   while(1)
   {
	   i--;
	   a=a*10;
       if(i==0)
		   break;
   }
   return (a+bb);
}

void get_p_q(ZZ &p,ZZ &q,int b=0)
{
	do
	{
		SetSeed(to_ZZ(time(NULL))); 
		RandomPrime(p,5-b); 
		SetSeed(to_ZZ(time(NULL)*to_ZZ(time(NULL))));
		RandomPrime(q,5-b);
	}while(q==p);
}

void create_sig_ver(ZZ p,ZZ q,ZZ &n,ZZ &a,ZZ &b,int bb=0)
{
	ZZ buffer;
	ZZ fn;
	fn=(p-1)*(q-1);
	n=p*q;
	do
	{
		SetSeed(to_ZZ(time(NULL)));
		RandomLen(a,4-bb);//
	}while(GCD(a,fn)!=1);
	ZZ b1,b2;
	XGCD(b1,b,b2,a,fn);
    if(b<0)
		b+=fn;
}

//RSA生成签名用的公钥密钥
void Rsa(ZZ &r_p,ZZ &r_q,ZZ &r_n,ZZ &r_a,ZZ &r_b,int b=0)
{
    get_p_q(r_p,r_q,b);
	create_sig_ver(r_p,r_q,r_n,r_a,r_b,b);
}
 
//ELGamal生成签名用的公钥密钥
void ELGamal(ZZ &e_p,ZZ &e_aa,ZZ &e_bb,ZZ &e_a)
{
	 ZZ p_,i,j,q;
		 bool aa_flag=false;

		 //生成p
		 do
		 {
			 SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL)));
			 GenGermainPrime(p_,20);//
			 e_p=2*p_+1;
		 }while(MillerWitness(e_p,p_)==1);

		 //生成本原元aa
		 do
		 {
			SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL)));
			e_aa=RandomBnd(e_p);
			for(aa_flag=true,q=2;q<e_p-1;q=NextPrime(q+1))
			{
				ZZ gcd=GCD(e_p-1,q);
				if(GCD(e_p-1,q)==1)//整除
					continue;
				else//幂次判断
				if(PowerMod(e_aa,(e_p-1)/gcd,e_p)==1)
				{
					aa_flag=false;
					break;
				}	
			}
		 }while(aa_flag==false);

		 //生成私钥a 
		 do
		 {
			 SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL)));
			 e_a=RandomBnd(e_p-1);
		 }while(e_a==0||GCD(e_p-1,e_a)!=1);


		 //计算bb
		 e_bb=PowerMod(e_aa,e_a,e_p);
}

void Alice(ZZ n,ZZ b,ZZ &r_p,ZZ &r_q,ZZ &r_n,ZZ &r_a,ZZ &r_b,ZZ &e_p,ZZ &e_aa,ZZ &e_bb,ZZ &e_a)
{
    int choose;
	do
	{
		cout<<"\n_Alice_\n";
		cout<<"Rsa(press 0) Or ELGamal(press 1) To Make Your Certificate=";
		cin>>choose;
	}while(choose!=0&&choose!=1);

	ZZ id;
    ZZ yid,yn,yb;
    ZZ rid,rn,rb;
    ZZ oid,on,ob;
	
	//id=8110810599101;
    id=43;

    if(choose==0)
	{
	   ofstream fout("certification.txt");
	   fout <<0<< "\n";
	   Rsa(r_p,r_q,r_n,r_a,r_b,-45);
      
       ZZ x=zzcat(id,zzcat(n,b));
       ZZ s=PowerMod(x,r_a,r_n);
	   
	   fout<<x<<endl;
	   fout<<s<<endl;
	   fout.close();

	   cout<<"Alice's id:"<<id<<endl;
	   cout<<"Alice's ver_:"<<x<<endl;
	   cout<<"Alice's s:"<<s<<endl;
	   cout<<"Alice's Certification:"<<x<<"-"<<s<<endl;
	 
	}
    else
	{
		 ofstream fout("certification.txt");
		 fout <<1<< "\n";
		 ELGamal(e_p,e_aa,e_bb,e_a);
	     //cout<<"e_p="<<e_p<<" e_aa="<<e_aa<<" e_bb="<<e_bb<<" e_a="<<e_a<<endl; 
        
         ZZ x=zzcat(id,zzcat(n,b));
         fout<<x<<endl;

		 //产生秘密随机数
	     ZZ k,k_;
		 do{
		     SetSeed(to_ZZ(time(NULL)));
			 k=RandomBnd(e_p-1);
		 }while(k==0||GCD(e_p-1,k)!=1);


		 ZZ b1,b2;
         ZZ sr=PowerMod(e_aa,k,e_p);
		 XGCD(b1,k_,b2,k,e_p-1);
		 ZZ so=(x-e_a*sr)*k_%(e_p-1);
         fout<<sr<<endl;
		 fout<<so<<endl;
	 
		 fout.close();
		 cout<<"Alice's id:"<<id<<endl;
	     cout<<"Alice's ver_:"<<x<<endl;
		 cout<<"Alice's s:"<<sr<<"_"<<so<<endl;
		 cout<<"Alice's Certification:"<<x<<"-"<<sr<<"_"<<so<<endl;
	
		 int pause;
		 cin>>pause;
	}
}

bool Rsa_ver(ZZ r_x,ZZ r_y,ZZ r_n,ZZ r_b)
{
	 if(r_x==PowerMod(r_y,r_b,r_n))
		return true;
	else
		return false;

}

bool ELGamal_ver(ZZ &x,ZZ &r,ZZ &o,ZZ &p,ZZ &aa,ZZ &bb)
{
 
	ZZ ver1,ver2;
	ver1=PowerMod(bb,r,p)*PowerMod(r,o,p);
	ver1=ver1%p;
	ver2=PowerMod(aa,x,p);

	if(ver1==ver2)
		return true;
	else
		return false;
}


void Bob(ZZ &r_n,ZZ &r_b, ZZ &e_p,ZZ &e_aa,ZZ &e_bb)
{
	  
	  cout<<"\n_Bob_\n";
	  //读入Alice证书
	  int choose;
	  ifstream fin("certification.txt");
	  fin>>choose;  
	  if(choose==0)
	  {
		 ZZ x;
		 ZZ s;
		 fin>>x;
		 fin>>s;

         cout<<"Bob get the cert:"<<x<<"-"<<s<<"\n";
         cout<<"Bob's validation:";
         if(Rsa_ver(x,s,r_n,r_b))
			cout<<"SUCCESS\n";
		 else
			cout<<"FAILURE\n";	   
	  }
	  else
	  {
          
		 ZZ x;
		 ZZ sr,so;
		 fin>>x;
		 fin>>sr;
		 fin>>so;

         cout<<"Bob get the cert:"<<x<<"-"<<sr<<"_"<<so<<endl;
         cout<<"Bob's validation:";
         if(ELGamal_ver(x,sr,so,e_p,e_aa,e_bb))
			cout<<"SUCCESS\n";
		 else
			cout<<"FAILURE\n";
	  }

	  fin.close();
}

void main()
{
     int pause;
	
	 //Alice的公钥私钥(程序生成)
	 ZZ p,q,n,a,b;

	 //TA的RSA的公钥私钥(生成),以及待验证消息(读入)
     ZZ r_p,r_q,r_n,r_a,r_b;
	  
	 //TA的ELGamal的公钥私钥(生成)，以及待验证消息(读入)
	 ZZ e_p,e_aa,e_bb,e_a;
	 
	 get_p_q(p,q,1);
	 create_sig_ver(p,q,n,a,b,1);
     //cout<<"p="<<p<<" q="<<q<<" n="<<n<<" a="<<a<<" b="<<b<<endl;

	 Alice(n,b,r_p,r_q,r_n,r_a,r_b,e_p,e_aa,e_bb,e_a);
     

	 Bob(r_n,r_b,e_p,e_aa,e_bb);


	 cin>>pause;
}