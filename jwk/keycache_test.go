package jwk

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {

	pk1 := &rsa.PublicKey{}

	ct := time.Now()
	s := &keyCache{
		keys: make(map[string]*cacheItem),
		ttl:  defaultCacheDuration,
		poll: defaultCacheExpirePoll,
		now:  func() time.Time { return ct },
	}

	k := s.getKey("fnord", "kid")
	require.Nil(t, k)
	s.putKey("fnord", "kid", pk1)
	k = s.getKey("fnord", "kid")
	require.Equal(t, k, pk1)

	ct = ct.Add(s.ttl)
	ct = ct.Add(-time.Second)

	// not expired
	k = s.getKey("fnord", "kid")
	require.Equal(t, k, pk1)

	ct = ct.Add(time.Second)
	ct = ct.Add(time.Second)

	// now expired
	k = s.getKey("fnord", "kid")
	require.Nil(t, k)

	require.Len(t, s.keys, 1)

	// put the same one back

	s.putKey("fnord", "kid", pk1)
	k = s.getKey("fnord", "kid")
	require.Equal(t, k, pk1)

	s.purgeExpired() // nop

	k = s.getKey("fnord", "kid")
	require.Equal(t, k, pk1)

	// purge it again

	ct = ct.Add(s.ttl)
	ct = ct.Add(time.Second)

	k = s.getKey("fnord", "kid")
	require.Nil(t, k)

	require.Len(t, s.keys, 1)

	s.purgeExpired() // actually delete

	require.Len(t, s.keys, 0)

	s.stopExpirePoll()
}
