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

ZZ zzget(ZZ a)
{
	ZZ i,b,bb;
	b=a;
    i=0;
	while(1)
	{
		i++;
		b=b/10;
		if(b==0)
			break;
	}
	b=1;
	i=i-2;
	while(1)
    {
	   i--;
	   b=b*10;
       if(i==0)
		   break;
    }
	return a%b;
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
void ELGamal(ZZ &e_p,ZZ &e_aa,ZZ &e_bb,ZZ &e_a,int bo=0)
{
	 ZZ p_,i,j,q;
		 bool aa_flag=false;

		 //生成p
		 do
		 {
			 SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL)));
			 GenGermainPrime(p_,16+bo);//
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

# define aid 43
# define bid 23

void make_cert(ZZ b,ZZ &r_p,ZZ &r_q,ZZ &r_n,ZZ &r_a,ZZ &r_b,ZZ &e_p,ZZ &e_aa,ZZ &e_bb,ZZ &e_a,int peo=1,bool first=true)
{
    int choose;
	do
	{
		if(peo==1)
			cout<<"\n_Alice_\n";
		else
			cout<<"\n_Bob_\n";
		cout<<"Rsa(press 0) Or ELGamal(press 1) To Make Your Certification:";
		cin>>choose;
	}while(choose!=0&&choose!=1);

	ZZ id;
    ZZ yid,yn,yb;
    ZZ rid,rn,rb;
    ZZ oid,on,ob;
	
	//id=8110810599101;
    if(peo==1)
		id=aid;
	else
		id=bid;
	
	if(choose==0)
	{
	    ofstream fout;
		if(peo==1)
		 fout.open("cert_Alice.txt");
		 else
		 fout.open("cert_Bob.txt");
	   fout <<0<< "\n";
      
       ZZ x=zzcat(id,b);
       ZZ s=PowerMod(x,r_a,r_n);
	   
	   fout<<x<<endl;
	   fout<<s<<endl;

	   fout.close();

	   if(peo==1)
	   {
			cout<<"Alice's id="<<id<<endl;
			cout<<"Alice's ver_="<<x<<endl;
			cout<<"Alice's s="<<s<<endl;
			cout<<"Alice's Certification="<<x<<"-"<<s<<endl;
	   }
	   else
	   {
			cout<<"Bob's id="<<id<<endl;
			cout<<"Bob's ver_="<<x<<endl;
			cout<<"Bob's s="<<s<<endl;
			cout<<"Bob's Certification="<<x<<"-"<<s<<endl;
	   }
	 
	}
    else
	{
		 ofstream fout;
		 if(peo==1)
		 fout.open("cert_Alice.txt");
		 else
		 fout.open("cert_Bob.txt");
		 fout <<1<< "\n";

	     //cout<<"e_p="<<e_p<<" e_aa="<<e_aa<<" e_bb="<<e_bb<<" e_a="<<e_a<<endl; 
        
         ZZ x=zzcat(id,b);
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
		 if(peo==1){
			cout<<"Alice's id="<<id<<endl;
			cout<<"Alice's ver_="<<x<<endl;
			cout<<"Alice's s="<<sr<<"_"<<so<<endl;
			cout<<"Alice's Certification="<<x<<"-"<<sr<<"_"<<so<<endl;}
	     else
		 {
			cout<<"Bob's id="<<id<<endl;
			cout<<"Bob's ver_="<<x<<endl;
			cout<<"Bob's s="<<sr<<"_"<<so<<endl;
			cout<<"Bob's Certification="<<x<<"-"<<sr<<"_"<<so<<endl;
		 }
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


bool ver_cert(ZZ &r_n,ZZ &r_b, ZZ &e_p,ZZ &e_aa,ZZ &e_bb,int peo=2)
{
	  
	  if(peo==1)
		cout<<"\n_Alice_\n";
	  else
        cout<<"\n_Bob_\n";
	  //读入证书
	  int choose;
	  ifstream fin;
	  if(peo==2)
	  fin.open("cert_Alice.txt");
	  else
	  fin.open("cert_Bob.txt");
	  fin>>choose;  
	  if(choose==0)
	  {
		 ZZ x;
		 ZZ s;
		 fin>>x;
		 fin>>s;

		 if(peo==2)
		 {
         cout<<"Bob gets the cert="<<x<<"-"<<s<<"\n";
         cout<<"Bob's validation:";
         }
		 else
		 {
			cout<<"Alice gets the cert="<<x<<"-"<<s<<"\n";
		    cout<<"Alice's validation:";
		 }
		 
		 if(Rsa_ver(x,s,r_n,r_b))
		 {
			cout<<"SUCCESS\n";
		    return true;
		 } 
		else
		{
			cout<<"FAILURE\n";	   
			return false;
		}
	  }
	  else
	  {
          
		 ZZ x;
		 ZZ sr,so;
		 fin>>x;
		 fin>>sr;
		 fin>>so;
		 
		 if(peo==2)
		 {
         cout<<"Bob gets the cert="<<x<<"-"<<sr<<"_"<<so<<"\n";
         cout<<"Bob's validation:";
         }
		 else
		 {
			cout<<"Alice gets the cert="<<x<<"-"<<sr<<"_"<<so<<"\n";
		    cout<<"Alice's validation:";
		 }
         
		 if(ELGamal_ver(x,sr,so,e_p,e_aa,e_bb))
		 {	
			 cout<<"SUCCESS\n";
		     return true;
		 }
		 else
		 {
			cout<<"FAILURE\n";
			return false;
		 }
	  }
	  fin.close();
}

//TA的RSA的公钥私钥(生成),以及待验证消息(读入)
ZZ r_p,r_q,r_n,r_a,r_b;
//TA的ELGamal的公钥私钥(生成)，以及待验证消息(读入)
ZZ e_p,e_aa,e_bb,e_a;
//Bob的RSA的公钥私钥(生成),以及待验证消息(读入)
ZZ br_p,br_q,br_n,br_a,br_b;
//Bob的ELGamal的公钥私钥(生成)，以及待验证消息(读入)
ZZ be_p,be_aa,be_bb,be_a;
//Alice的RSA的公钥私钥(生成),以及待验证消息(读入)
ZZ ar_p,ar_q,ar_n,ar_a,ar_b;
//Alice的ELGamal的公钥私钥(生成)，以及待验证消息(读入)
ZZ ae_p,ae_aa,ae_bb,ae_a;

ZZ mti_p,mti_n,mti_aa;
ZZ au,bu,av,bv,ru,rv,su,sv,keyu,keyv;


void Alice(ZZ &r1,ZZ &r2,ZZ &y1,ZZ &y1_,ZZ &y2,ZZ &y2_,int step=0,bool rsa=true)
{
	if(step==0)
	{
		SetSeed(to_ZZ(time(NULL)));
		au=RandomBnd(999);//随机数任意
		au+=1;
		bu=PowerMod(mti_aa,au,mti_p);
		
		SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL)));
		ru=RandomBnd(999);//随机数任意
		ru+=1;
		su=PowerMod(mti_aa,ru,mti_p);
	}

	if(step==2)
	{
		SetSeed(to_ZZ(time(NULL)));
	    r2=RandomBnd(99);
	    r2+=1;
        
        ZZ Bid;
		Bid=23;
		ZZ x=zzcat(Bid,zzcat(r1,r2));

		if(rsa)
			y1=PowerMod(x,ar_a,ar_n);
		else
		{
			ZZ k,k_;
			do{
				 SetSeed(to_ZZ(time(NULL)));
				 k=RandomBnd(ae_p-1);
			}while(k==0||GCD(ae_p-1,k)!=1);

			ZZ b1,b2;
			y1=PowerMod(ae_aa,k,ae_p);
			XGCD(b1,k_,b2,k,ae_p-1);
			y1_=(x-ae_a*y1)*k_%(ae_p-1);
		}
	}
	else if(step==4)
	{
		if(ver_cert(r_n,r_b,e_p,e_aa,e_bb,1))
		{
			ZZ Bid,Aid;
			Bid=23;
			Aid=43;	
			ZZ x=zzcat(Aid,r2);

			if(rsa)
				if(Rsa_ver(x,y2,br_n,br_b))
					cout<<"Alice Accepts It"<<endl;
				else
					cout<<"Alice Refuses It"<<endl; 
			else
				if(ELGamal_ver(x,y2,y2_,be_p,be_aa,be_bb))
					cout<<"Alice Accepts It"<<endl;
				else
					cout<<"Alice Refuses It"<<endl; 
		   
			ifstream fin("cert_Bob.txt");
			ZZ bvin;
			fin>>bvin;
			fin>>bvin;
			bvin=zzget(bvin);
            keyu=PowerMod(sv,au,mti_p)*PowerMod(bv,ru,mti_p);
			fin.close();

		}
	}
}

void Bob(ZZ &r1,ZZ &r2,ZZ &y1,ZZ &y1_,ZZ &y2,ZZ &y2_,int step=0,bool rsa=true)
{
	if(step==0)
	{
		SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL)));
		av=RandomBnd(999);//随机数任意
		av+=1;
		bv=PowerMod(mti_aa,av,mti_p);

		SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL))*to_ZZ(time(NULL)));
		rv=RandomBnd(999);//随机数任意
		rv+=1;
		sv=PowerMod(mti_aa,rv,mti_p);
	}

	if(step==1)
	{
		SetSeed(to_ZZ(time(NULL)));
	    r1=RandomBnd(99);
	    r1+=1;
	}
	else if(step==3)
	{
		
		if(ver_cert(r_n,r_b,e_p,e_aa,e_bb,2))
		{
			ZZ Bid,Aid;
			Bid=23;
			Aid=43;
			ZZ x=zzcat(Bid,zzcat(r1,r2));
			if(rsa)
			{ 
				if(Rsa_ver(x,y1,ar_n,ar_b))
					cout<<"Bob Accepts It"<<endl;
				else
					cout<<"Bob Refuses It"<<endl; 
				x=zzcat(Aid,r2);
				y2=PowerMod(x,br_a,br_n);
			}
			else
			{
				
				if(ELGamal_ver(x,y1,y1_,ae_p,ae_aa,ae_bb))
					cout<<"Bob Accepts It"<<endl;
				else
					cout<<"Bob Refuses It"<<endl; 
				
                x=zzcat(Aid,r2);
				ZZ k,k_;
				do{
					 SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL)));
					k=RandomBnd(be_p-1);
				}while(k==0||GCD(be_p-1,k)!=1);

				ZZ b1,b2;
				y2=PowerMod(be_aa,k,be_p);
				XGCD(b1,k_,b2,k,be_p-1);
			    y2_=(x-be_a*y2)*k_%(be_p-1);
			}

			ifstream fin("cert_Alice.txt");
			ZZ buf,buin;
			fin>>buf;
			fin>>buin;
			buin=zzget(buin);
			keyv=PowerMod(su,av,mti_p)*PowerMod(bu,rv,mti_p);
		 
			fin.close();
		}
	}
}


void main()
{
     int pause;
 
	 ZZ r1,r2,y1,y1_,y2,y2_;
	 ZZ buf1,buf2,buf3;
     buf3=-1;

	 //生成mti
	 ELGamal(mti_p,mti_aa,buf1,buf2);
	 mti_n=mti_p-1;
	 Bob(r1,r2,y1,y1_,y2,y2_);
	 Alice(r1,r2,y1,y1_,y2,y2_);

     //cout<<"mti_p="<<mti_p<<endl<<"mti_aa="<<mti_aa<<endl<<"mti_n="<<mti_n<<endl;
	 //cout<<"au="<<au<<endl<<"bu="<<bu<<endl<<"av="<<av<<endl<<"bv="<<bv<<endl<<"ru="<<ru<<endl<<"rv="<<rv<<endl<<"su="<<su<<endl<<"sv="<<sv<<endl;
	 
	 Rsa(r_p,r_q,r_n,r_a,r_b,-35);
	 ELGamal(e_p,e_aa,e_bb,e_a);
	 make_cert(bu,r_p,r_q,r_n,r_a,r_b,e_p,e_aa,e_bb,e_a,1);
	 make_cert(bv,r_p,r_q,r_n,r_a,r_b,e_p,e_aa,e_bb,e_a,2);
     
	 //ver_cert(r_n,r_b,e_p,e_aa,e_bb,2);
     //ver_cert(r_n,r_b,e_p,e_aa,e_bb,1);

	 
	 cout<<"\n\n\n----------公钥环境下的交互认证----------\n";
     cout<<"请选择交互认证签名方案:Rsa(press 0),ELGamal(press 1)";
     int choose=0;
	 do{
		 cin>>choose;
	 }while(choose!=1&&choose!=0);


	 if(choose==0)
	 {
		Rsa(ar_p,ar_q,ar_n,ar_a,ar_b,-40);\
		//cout<<"ar_p="<<ar_p<<" ar_q="<<ar_q<<" ar_n="<<ar_n<<" ar_a="<<ar_a<<" ar_b="<<ar_b<<endl;
		Rsa(br_p,br_q,br_n,br_a,br_b,-40);
	    //cout<<"br_p="<<br_p<<" br_q="<<br_q<<" br_n="<<br_n<<" br_a="<<br_a<<" br_b="<<br_b<<endl;

        Bob(r1,r2,y1,y1_,y2,y2_,1);
		Alice(r1,r2,y1,y1_,y2,y2_,2);
		Bob(r1,r2,y1,y1_,y2,y2_,3);
        Alice(r1,r2,y1,y1_,y2,y2_,4);
		
	 }
	 else
	 {
		ELGamal(ae_p,ae_aa,ae_bb,ae_a,4);
		//cout<<"ar_p="<<ar_p<<" ar_q="<<ar_q<<" ar_n="<<ar_n<<" ar_a="<<ar_a<<" ar_b="<<ar_b<<endl;
		ELGamal(be_p,be_aa,be_bb,be_a,4);
	    //cout<<"br_p="<<br_p<<" br_q="<<br_q<<" br_n="<<br_n<<" br_a="<<br_a<<" br_b="<<br_b<<endl;
		
		Bob(r1,r2,y1,y1_,y2,y2_,1,false);
		Alice(r1,r2,y1,y1_,y2,y2_,2,false);
		Bob(r1,r2,y1,y1_,y2,y2_,3,false);
        Alice(r1,r2,y1,y1_,y2,y2_,4,false);
	 }
	    

	 cout<<endl<<endl<<"----------公共密钥验证----------"<<endl;
     cout<<"Alice's key="<<keyu<<endl;
	 cout<<"Bob's key="<<keyv<<endl;

	 cin>>pause;
}