package org.googlecode.tapestry5jsecurity.realm;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.shiro.realm.Realm;

public class RealmCollectionImpl implements RealmCollection {

	private final Collection<Realm> delegat = new ArrayList<Realm>();
	
	@Override
	public boolean add(Realm e) {
		return delegat.add(e);
	}

	@Override
	public boolean addAll(Collection<? extends Realm> c) {
		return delegat.addAll(c);
	}

	@Override
	public void clear() {
		delegat.clear();
	}

	@Override
	public boolean contains(Object o) {
		return delegat.contains(o);
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return delegat.containsAll(c);
	}

	@Override
	public boolean isEmpty() {
		return delegat.isEmpty();
	}

	@Override
	public Iterator<Realm> iterator() {
		return delegat.iterator();
	}

	@Override
	public boolean remove(Object o) {
		return delegat.remove(o);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return delegat.removeAll(c);
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return delegat.retainAll(c);
	}

	@Override
	public int size() {
		return delegat.size();
	}

	@Override
	public Object[] toArray() {
		return delegat.toArray();
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return delegat.toArray(a);
	}

}
