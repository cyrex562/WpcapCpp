// -*-Mode: C++;-*-

#include <hat.H>

template <class T>
void Hat<T>::init( const size_t aExpectedSize )
{
    setPower( recommendedPower(aExpectedSize) );
    numElements = 0;

    top = NULL;
    topUsed = 0;
}

template <class T>
Hat<T>::Hat( const size_t aExpectedSize )
{
    init( aExpectedSize );
}

template <class T>
Hat<T>::Hat( const Hat<T> &hat )
{
    init( 0 );
    (*this) = hat;
}

template <class T>
Hat<T>::~Hat()
{
    for( size_t i = 0; i < topUsed; i++ )
	delete [] top[i];
    delete [] top;
}

template <class T>
Hat<T>	&Hat<T>::operator=(const Hat<T> &hat)
{
    if( this == &hat )
	return *this;

    // Delete any existing elements.
    clear();
    // Set ourselves to the best size.
    setMaxElements( hat.elements() );
    for( size_t i = 0; i < hat.elements(); i++ )
	append( hat[i], 0 );	// do not resize when appending.
    return *this;
}

template <class T>
int	Hat<T>::operator==(const Hat<T> &hat) const
{
    if( numElements != hat.numElements )
	return 0;
    for( size_t i = 0; i < numElements; i++ )
	if( !((*this)[i] == hat[i]) )
	    return 0;
    return 1;
}

template <class T>
size_t	Hat<T>::recommendedPower( const size_t s ) const
{
    // compute the root of s to the nearest greater power of 2
    const size_t powerMin = 1; // set a resonable minimum
    size_t p;
    for( p = powerMin; s > (1<<(p<<1)); p++ )
	;
    return p;
}

template <class T>
void Hat<T>::addLeaf( const T &aValue, const int doResize )
{
    if( topUsed % topSize() == 0 )
    {
	int	growTop = 1;
	if( doResize && shouldResize() )
	{
	    resize( numElements );
	    // Check if after the resize we have room.
	    if( topIndex(numElements) < topUsed )
	    {
		(*this)[numElements++] = aValue;
		return;
	    }
	    // Check if we have room for a new leaf.
	    if( topUsed % topSize() != 0 )
		growTop = 0;
	}
	if( growTop )
	{
	    // Increase the top array by topSize.
	    T	**topNew = new T * [ topUsed + topSize() ];
	    for( size_t i = 0; i < topUsed; i++ )
		topNew[i] = top[i];
	    delete [] top;
	    top = topNew;
	}
    }
	top[topUsed] = new T [leafSize()];
    top[topUsed][0] = aValue;
    topUsed++;
    numElements++;
}

template <class T>
void	Hat<T>::resize( const size_t newExpectedSize )
{
    size_t	i, j;

    Hat<T>	hatNew( newExpectedSize );
    if( hatNew.power == power )
	return;

    for( i = 0, j = 0; i < numElements; i++ )
    {
	hatNew.append( (*this)[i], 0 );	// append, but do not resize again

	// delete the leaves as we go - this decreases memory overhead.
	if( ++j == leafSize() )
	{
	    delete [] top[topIndex(i)];
	    j = 0;
	}
    }

    // delete any unused leaves.
    for( i = topIndex(numElements); i < topUsed; i++ )
	delete [] top[i];

    // assign the new array to the old.
    delete top;
    top = hatNew.top;
    setPower( hatNew.power );
    topUsed = hatNew.topUsed;

    // clean up so nothing gets corrupted.
    hatNew.numElements = 0;
    hatNew.topUsed = 0;
    hatNew.top = NULL;
}

template <class T>
void Hat<T>::setMaxElements( const size_t maxElements )
{
    if( maxElements > numElements )
    {
	resize( maxElements );
	T value;
	for( size_t i = numElements; i < maxElements; i++ )
	    append( value, 0 );
    }
    else if( maxElements < numElements )
    {
	numElements = maxElements;
	if( shouldResize() )
	    resize( numElements );
    }
}

template <class T>
int Hat<T>::contains( const T& e ) const
{
    for( size_t i = 0; i < numElements; i++ )
	if( (*this)[i] == e )
	    return 1;
    return 0;
}

template <class T>
size_t Hat<T>::index( const T& e ) const
{
    for( size_t i = 0; i < numElements; i++ )
	if( (*this)[i] == e )
	    return i;
    return numElements + 1;
}

template <class T>
void Hat<T>::insertAt( const size_t i, const T& a )
{
    if( i == numElements )
    {
	append( a );
	return;
    }
    setMaxElements( numElements + 1 );
    for( size_t j = numElements-1; j > i; j-- )
	(*this)[j+1] = (*this)[j];
    (*this)[i] = a;
}

template <class T>
size_t Hat<T>::occurrencesOf( const T& a ) const
{
    size_t j = 0;
    for( size_t i = 0; i < numElements; i++ )
	if( (*this)[i] == a )
	    j++;
    return j;
}

template <class T>
size_t Hat<T>::removeAll( const T& a )
{
    size_t src, dest = 0;
    for( src = 0; src < numElements; src++ )
	if( !((*this)[src] == a) )
	{
	    if( dest != src )
		(*this)[dest] = (*this)[src];
	    dest++;
	}
    if( dest != src )
	setMaxElements( dest );
    return src - dest;
}

template <class T>
T Hat<T>::removeAt( size_t i )
{
    T	save = (*this)[i];
    for( ; i < numElements - 1; i++ )
	(*this)[i] = (*this)[i+1];
    setMaxElements( numElements - 1 );
    return save;
}

