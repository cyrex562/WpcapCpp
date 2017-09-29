
#ifndef Hat_H
#define Hat_H

#include <stdlib.h>

// These macros ensure the these calculations get
// inlined even for stupid compilers.
#define GetTopIndex(i) ((i)>>power)
#define GetLeafIndex(i) ((i)&leafMask)

template <class T>
class Hat
{
public:
    Hat( const size_t aExpectedSize = 0 );
    Hat( const Hat &hat );
    Hat &operator=( const Hat &hat );
    ~Hat();

    T &operator[](const size_t i)
    {
	return top[GetTopIndex(i)][GetLeafIndex(i)];
    }
    T operator[](const size_t i) const
	{
	return top[GetTopIndex(i)][GetLeafIndex(i)];
    }
    T &operator()( const size_t i) { return (*this)[i]; }
    T operator()( const size_t i) const { return (*this)[i]; }

    int operator==( const Hat &hat ) const;

    void append( const T &aValue, const int doResize = 1 )
    {
	if( GetLeafIndex(numElements) == 0 )
	    addLeaf( aValue, doResize );
	else
	    (*this)[numElements++] = aValue;
    }
    T &at(const size_t i) { return (*this)[i]; }
    T at(const size_t i) const { return (*this)[i]; }
	void clear() { setMaxElements(0); }
    int	contains( const T &value ) const;
    size_t entries() const { return numElements; }
    size_t elements() const { return numElements; }

    T first() const { return (*this)[0]; }
    size_t index( const T& a ) const;
    void insert( const T& a ) { append(a); }
    void insertAt( const size_t i, const T& a );
    int isEmpty() const { return numElements == 0; }
    T last() const { return (*this)[numElements-1]; }
    size_t length() const { return numElements; }
    size_t occurrencesOf( const T& a ) const;
    void prepend( T &a ) { insertAt(0, a); }
	void remove( const T& a )
	{
		size_t f = index(a);
		if( f < numElements )
			removeAt(f);
    }
    size_t removeAll( const T& a );
    T removeAt( size_t i );
    T removeFirst() { return removeAt(0); }
    T removeLast() { return removeAt(numElements-1); }

    void setMaxElements( const size_t maxElements );

private:
    size_t leafSize() const { return 1<<power; }
    size_t topSize() const { return 1<<power; }
    size_t topIndex( const unsigned i ) const { return GetTopIndex(i); }
    size_t leafIndex( const unsigned i ) const { return GetLeafIndex(i); }
    void   init( const size_t aExpectedSize );
    void resize( const size_t newExpectedSize );
    
    size_t recommendedPower( const size_t s ) const;
    void setPower( const size_t p )
    {
	power = p;
	leafMask = leafSize()-1;
    }
    void addLeaf( const T &aValue, const int doResize = 1 );

    int shouldResize() const
    {
	// Smooth the growth of the HAT around resize boundaries.
	const int growFactor = 2;
	return numElements >= growFactor * topSize() * leafSize() ||
	    growFactor * numElements <= topSize() * leafSize();
    }
    
    T	**top;		     // top points to leaves
    size_t	topUsed;     // amount of top actually used
    size_t	power;	     // power of 2 used for leaves and top
    size_t	leafMask;    // used to compute the leaf index
    size_t	numElements; // number of elements in the array
};

#undef GetTopIndex
#undef GetLeafIndex

#ifdef INLINE_TEMPLATES
#include <hat.t>
#endif

#endif // Hat_H

