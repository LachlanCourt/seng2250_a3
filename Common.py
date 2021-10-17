class Common: 
    def powmod2(b, e, n):
        if n == 1:
            return 0
        rs = 1
        while (e > 0):
            if (e & 1) == 1:
                rs = (rs * b) % n
            e = e >> 1
            b = (b * b) % n
        return rs
