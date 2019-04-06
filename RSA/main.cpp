#include <NTL/ZZ.h>
#include <fstream.h>
#include <time.h>

NTL_CLIENT

void get_p_q(ZZ &p,ZZ &q)
{
	do{
	SetSeed(to_ZZ(time(NULL))); 
	RandomPrime(p,512); 
	SetSeed(to_ZZ(time(NULL))*to_ZZ(time(NULL)));
	RandomPrime(q,512);
	}while(p==q);
}

void Alice(ZZ p,ZZ q,ZZ &n,ZZ &a,ZZ &b,ZZ &x,ZZ &y)
{
	cout<<"_Alice_\n";
	ZZ buffer;
	ZZ fn;
	fn=(p-1)*(q-1);
	n=p*q;
	do
	{
		SetSeed(to_ZZ(time(NULL)));
		RandomLen(a,1023);
	}while(GCD(a,fn)!=1);
	ZZ b1,b2;
	XGCD(b1,b,b2,a,fn);
    if(b<0)
		b+=fn;
	cout<<"Input News=";
	cin>>x;
	y=PowerMod(x, a, n);
	cout<<"Signature="<<y;
}

void Oscar(ZZ &x,ZZ &y)
{
	char q;
	ZZ xx,yy;
	cout<<"_Oscar_\n";
	cout<<"chang News or Signature(press 0 to give up)\n";
    cout<<"News=";
	cin>>xx;
	cout<<"Signature=";
	cin>>yy;

	if(xx!=0)
		x=xx;
	if(yy!=0)
		y=yy;
}

void Bob(ZZ n,ZZ b,ZZ x,ZZ y)
{
	cout<<"_Bob_\n";
	cout<<"Bob get News="<<x<<"\nSignature="<<y<<"\nVerification Result:";
    if(x==PowerMod(y, b, n))
		cout<<"SUCCESS";
	else
		cout<<"FAILURE";
}

void main()
{
    ZZ p,q,n,a,b,x,y,pause;
	get_p_q(p,q);
	Alice(p,q,n,a,b,x,y);
	cout<<endl<<endl;
    Oscar(x,y);
	cout<<endl;
	Bob(n,b,x,y);
   
	cin >> pause;    //用于暂停，观测数据
}
