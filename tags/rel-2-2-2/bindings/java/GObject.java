package com.entrouvert.lasso;
import java.util.*;

class GObject {
        private long cptr;

        protected GObject(long ptr) {
                if (ptr == 0) {
                    throw new RuntimeException("Error creating " + getClass().getName());
                }
                cptr = ptr;
        }
        protected Map arrayToMap(Object[] arr) {
            Map map = new HashMap();
            if (arr == null)
                return map;
            if (arr.length % 2 != 0)
                throw new IllegalArgumentException("arr must of an even size");
            int i;
            for (i=0;i<arr.length;i+=2) {
                map.put(arr[i],arr[i+1]);
            }
            return map;
        }
        protected void mapToArray(Map map, Object[] arr) {
            int s = map.size();
            if (map == null)
                return;
            Iterator it;
            it = map.entrySet().iterator();
            int i = 0;
            while (it.hasNext() && i < 2*s) {
                Map.Entry e = (Map.Entry)it.next();
                arr[i++] = (Object)e.getKey();
                arr[i++] = (Object)e.getValue();
            }
        }
        protected void listToArray(List list, Object[] arr) {
            Iterator it = list.iterator();
            int s = arr.length;
            int i = 0;
            while (it.hasNext() && i < s) {
                arr[i++] = (Object)it.next();
            }
        }
        protected void finalize() throws Throwable {
            LassoJNI.destroy(cptr);
        }
}
