# Race Condition Vulnerabilities

## Read-Modify-Write Without Atomicity

The classic pattern: read a value, compute a new value, write it back. If two threads interleave, one write is lost.

### Double-Spend / Balance Manipulation

**Python (Django ORM) - VULNERABLE:**
```python
def transfer(request):
    sender = Account.objects.get(id=request.user.id)
    amount = Decimal(request.POST['amount'])
    if sender.balance >= amount:          # CHECK
        sender.balance -= amount          # MODIFY
        sender.save()                     # WRITE
        recipient = Account.objects.get(id=request.POST['to'])
        recipient.balance += amount
        recipient.save()
```
Two concurrent requests both read balance=100, both pass the check, both deduct 100 => balance goes to -100.

**Python (Django) - FIXED with select_for_update:**
```python
from django.db import transaction

def transfer(request):
    amount = Decimal(request.POST['amount'])
    with transaction.atomic():
        sender = Account.objects.select_for_update().get(id=request.user.id)
        if sender.balance >= amount:
            sender.balance -= amount
            sender.save()
            recipient = Account.objects.select_for_update().get(id=request.POST['to'])
            recipient.balance += amount
            recipient.save()
```

**Python (SQLAlchemy) - VULNERABLE:**
```python
def approve_request(request_id, approver_id):
    req = session.query(Request).get(request_id)
    if req.status == 'pending':
        req.status = 'approved'
        req.approved_by = approver_id
        session.commit()
```

**Python (SQLAlchemy) - FIXED with optimistic locking:**
```python
from sqlalchemy import event
from sqlalchemy.orm import validates

class Request(Base):
    __tablename__ = 'requests'
    id = Column(Integer, primary_key=True)
    status = Column(String)
    version = Column(Integer, default=0)

def approve_request(request_id, approver_id):
    req = session.query(Request).with_for_update().get(request_id)
    if req.status == 'pending':
        req.status = 'approved'
        req.approved_by = approver_id
        req.version += 1
        session.commit()
```

**Java (JPA) - VULNERABLE:**
```java
@Transactional
public void withdraw(Long accountId, BigDecimal amount) {
    Account account = accountRepository.findById(accountId).orElseThrow();
    if (account.getBalance().compareTo(amount) >= 0) {
        account.setBalance(account.getBalance().subtract(amount));
        accountRepository.save(account);
    }
}
```

**Java (JPA) - FIXED with pessimistic lock:**
```java
@Transactional
public void withdraw(Long accountId, BigDecimal amount) {
    Account account = accountRepository.findByIdWithLock(accountId);
    // where findByIdWithLock uses @Lock(LockModeType.PESSIMISTIC_WRITE)
    if (account.getBalance().compareTo(amount) >= 0) {
        account.setBalance(account.getBalance().subtract(amount));
        accountRepository.save(account);
    }
}

// Repository:
@Lock(LockModeType.PESSIMISTIC_WRITE)
@Query("SELECT a FROM Account a WHERE a.id = :id")
Account findByIdWithLock(@Param("id") Long id);
```

**Java (JPA) - FIXED with optimistic locking:**
```java
@Entity
public class Account {
    @Version
    private Long version;
    // ...
}
// JPA automatically checks version on update; throws OptimisticLockException on conflict
```

**Go - VULNERABLE:**
```go
func (s *Service) Transfer(ctx context.Context, fromID, toID int64, amount float64) error {
    sender, _ := s.repo.GetAccount(ctx, fromID)
    if sender.Balance >= amount {
        sender.Balance -= amount
        s.repo.UpdateAccount(ctx, sender)
        recipient, _ := s.repo.GetAccount(ctx, toID)
        recipient.Balance += amount
        s.repo.UpdateAccount(ctx, recipient)
    }
    return nil
}
```

**Go - FIXED with database-level atomicity:**
```go
func (s *Service) Transfer(ctx context.Context, fromID, toID int64, amount float64) error {
    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    // Row-level lock via SELECT ... FOR UPDATE
    var balance float64
    err = tx.QueryRowContext(ctx,
        "SELECT balance FROM accounts WHERE id = $1 FOR UPDATE", fromID,
    ).Scan(&balance)
    if err != nil {
        return err
    }
    if balance < amount {
        return errors.New("insufficient funds")
    }

    _, err = tx.ExecContext(ctx,
        "UPDATE accounts SET balance = balance - $1 WHERE id = $2", amount, fromID)
    if err != nil {
        return err
    }
    _, err = tx.ExecContext(ctx,
        "UPDATE accounts SET balance = balance + $1 WHERE id = $2", amount, toID)
    if err != nil {
        return err
    }
    return tx.Commit()
}
```

**JavaScript (Mongoose) - VULNERABLE:**
```javascript
async function redeemCoupon(userId, couponCode) {
  const coupon = await Coupon.findOne({ code: couponCode });
  if (coupon && coupon.usesRemaining > 0) {
    coupon.usesRemaining -= 1;
    await coupon.save();
    await applyDiscount(userId, coupon.discount);
  }
}
```

**JavaScript (Mongoose) - FIXED with atomic update:**
```javascript
async function redeemCoupon(userId, couponCode) {
  const result = await Coupon.findOneAndUpdate(
    { code: couponCode, usesRemaining: { $gt: 0 } },
    { $inc: { usesRemaining: -1 } },
    { new: true }
  );
  if (result) {
    await applyDiscount(userId, result.discount);
  }
}
```

---

## TOCTOU (Time-of-Check-to-Time-of-Use)

### File Operations

**Python - VULNERABLE:**
```python
import os

def write_log(filepath, data):
    if os.path.exists(filepath):           # CHECK
        if os.access(filepath, os.W_OK):   # CHECK
            with open(filepath, 'w') as f: # USE (file may have changed)
                f.write(data)
```
Between the check and the open, an attacker could replace the file with a symlink to /etc/passwd.

**Python - FIXED (use EAFP, handle errors):**
```python
import os

def write_log(filepath, data):
    # Resolve symlinks, validate path prefix
    real_path = os.path.realpath(filepath)
    if not real_path.startswith('/var/log/app/'):
        raise ValueError("Invalid log path")
    try:
        fd = os.open(real_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'w') as f:
            f.write(data)
    except OSError as e:
        log.error(f"Failed to write log: {e}")
```

### Auth Check TOCTOU

**Python - VULNERABLE:**
```python
def update_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    if doc.owner_id == request.user.id:    # CHECK ownership
        # ... some processing ...
        doc.content = request.POST['content']
        doc.save()                          # USE - ownership may have changed
```

**Go - VULNERABLE:**
```go
func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("path")
    info, err := os.Stat(path)           // CHECK
    if err != nil || info.IsDir() {
        http.Error(w, "invalid", 400)
        return
    }
    // Between Stat and Remove, path could become a symlink
    os.Remove(path)                       // USE
}
```

---

## Multi-Step Operations With Gaps

### Check-Then-Act in Financial Operations

**Python - VULNERABLE:**
```python
def purchase(request):
    user = User.objects.get(id=request.user.id)
    item = Item.objects.get(id=request.POST['item_id'])

    # Step 1: Check balance
    if user.wallet_balance >= item.price:
        # Step 2: Create order (GAP - balance not locked)
        order = Order.objects.create(user=user, item=item, total=item.price)
        # Step 3: Deduct balance
        user.wallet_balance -= item.price
        user.save()
        # Step 4: Deliver item
        deliver_item(order)
```

### Approval Workflow Gap

**Java - VULNERABLE:**
```java
@PostMapping("/approve")
public ResponseEntity<?> approveExpense(@RequestParam Long expenseId) {
    Expense expense = expenseRepo.findById(expenseId).orElseThrow();

    // Check: still pending?
    if (expense.getStatus() != ExpenseStatus.PENDING) {
        return ResponseEntity.badRequest().body("Already processed");
    }

    // GAP: between check and update, another approver could also approve
    expense.setStatus(ExpenseStatus.APPROVED);
    expense.setApprovedBy(getCurrentUser().getId());
    expenseRepo.save(expense);

    disburse(expense); // Money sent twice if two approvers race
    return ResponseEntity.ok("Approved");
}
```

**Java - FIXED:**
```java
@Transactional
@PostMapping("/approve")
public ResponseEntity<?> approveExpense(@RequestParam Long expenseId) {
    int updated = expenseRepo.approveIfPending(expenseId, getCurrentUser().getId());
    // SQL: UPDATE expenses SET status='APPROVED', approved_by=?
    //      WHERE id=? AND status='PENDING'
    if (updated == 0) {
        return ResponseEntity.badRequest().body("Already processed");
    }
    Expense expense = expenseRepo.findById(expenseId).orElseThrow();
    disburse(expense);
    return ResponseEntity.ok("Approved");
}
```

---

## Missing Idempotency Controls

### Duplicate Form Submissions

**JavaScript (Express) - VULNERABLE:**
```javascript
app.post('/payment', async (req, res) => {
  const { amount, recipient } = req.body;
  await processPayment(req.user.id, recipient, amount);
  res.json({ success: true });
  // Clicking submit twice or replaying request = double payment
});
```

**JavaScript (Express) - FIXED with idempotency key:**
```javascript
app.post('/payment', async (req, res) => {
  const idempotencyKey = req.headers['idempotency-key'];
  if (!idempotencyKey) {
    return res.status(400).json({ error: 'Idempotency-Key header required' });
  }

  // Atomic check-and-set
  const [record, created] = await IdempotencyRecord.findOrCreate({
    where: { key: idempotencyKey },
    defaults: { status: 'processing', userId: req.user.id }
  });

  if (!created) {
    // Already processed or in-progress
    return res.status(200).json(record.response);
  }

  try {
    const result = await processPayment(req.user.id, req.body.recipient, req.body.amount);
    await record.update({ status: 'completed', response: result });
    res.json(result);
  } catch (err) {
    await record.destroy(); // Allow retry on failure
    res.status(500).json({ error: 'Payment failed' });
  }
});
```

**Go - Idempotency with Redis:**
```go
func (h *Handler) HandlePayment(w http.ResponseWriter, r *http.Request) {
    key := r.Header.Get("Idempotency-Key")
    if key == "" {
        http.Error(w, "missing idempotency key", 400)
        return
    }

    // SETNX = atomic set-if-not-exists
    set, err := h.redis.SetNX(r.Context(), "idemp:"+key, "processing", 24*time.Hour).Result()
    if err != nil {
        http.Error(w, "internal error", 500)
        return
    }
    if !set {
        // Already processed
        cached, _ := h.redis.Get(r.Context(), "idemp:result:"+key).Result()
        w.Write([]byte(cached))
        return
    }

    result, err := h.processPayment(r)
    if err != nil {
        h.redis.Del(r.Context(), "idemp:"+key)
        http.Error(w, "failed", 500)
        return
    }
    h.redis.Set(r.Context(), "idemp:result:"+key, result, 24*time.Hour)
    w.Write([]byte(result))
}
```

---

## Rate Limit / Quota Bypass via Concurrent Requests

### Bypass Pattern

If a rate limiter uses a read-then-increment pattern, concurrent requests all read the same counter value before any increment lands.

**Python - VULNERABLE rate limiter:**
```python
def check_rate_limit(user_id):
    count = redis_client.get(f"rate:{user_id}")
    if count and int(count) >= 100:
        raise RateLimitExceeded()
    redis_client.incr(f"rate:{user_id}")
    # 50 concurrent requests all read count=99, all pass, all increment
```

**Python - FIXED with atomic Lua script:**
```python
RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if current > tonumber(ARGV[1]) then
    return 0
end
return 1
"""

def check_rate_limit(user_id, limit=100, window=3600):
    allowed = redis_client.eval(RATE_LIMIT_SCRIPT, 1,
        f"rate:{user_id}", limit, window)
    if not allowed:
        raise RateLimitExceeded()
```

### Coupon / Promo Code Abuse

**JavaScript - VULNERABLE:**
```javascript
async function applyCoupon(userId, code) {
  const usage = await CouponUsage.count({ where: { userId, code } });
  if (usage >= 1) throw new Error('Already used');
  // GAP: concurrent requests bypass the count check
  await CouponUsage.create({ userId, code });
  await applyDiscount(userId);
}
```

**JavaScript - FIXED with unique constraint:**
```javascript
async function applyCoupon(userId, code) {
  try {
    // DB unique constraint on (userId, code) prevents duplicates atomically
    await CouponUsage.create({ userId, code });
    await applyDiscount(userId);
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') {
      throw new Error('Already used');
    }
    throw err;
  }
}
```

---

## Framework-Specific Patterns

### Django ORM
| Vulnerable | Safe |
|---|---|
| `obj = Model.objects.get(...)` then `obj.field = x; obj.save()` | `Model.objects.filter(...).update(field=F('field') - amount)` |
| `if obj.count < limit: obj.count += 1` | `Model.objects.select_for_update().get(...)` inside `transaction.atomic()` |
| `obj.save()` (saves ALL fields, overwrites concurrent changes) | `obj.save(update_fields=['specific_field'])` |

### SQLAlchemy
| Vulnerable | Safe |
|---|---|
| `session.query(M).get(id)` then modify & commit | `session.query(M).with_for_update().get(id)` |
| No version column | `@version_id_col` or manual `WHERE version = :v` |

### JPA / Hibernate
| Vulnerable | Safe |
|---|---|
| `findById()` without locking | `@Lock(LockModeType.PESSIMISTIC_WRITE)` |
| No `@Version` field | Add `@Version private Long version;` |

### Mongoose (MongoDB)
| Vulnerable | Safe |
|---|---|
| `findOne` + modify + `save()` | `findOneAndUpdate` with atomic operators (`$inc`, `$set`) |
| Check-then-insert | Unique index + catch duplicate key error |

---

## Detection Signals

### Grep Patterns

```bash
# Django: find read-modify-write without select_for_update
grep -rn '\.objects\.get\(' --include='*.py' | grep -v 'select_for_update'
grep -rn '\.save()' --include='*.py' | head -50

# Django: find non-atomic increments
grep -rn 'balance\|count\|quantity\|stock\|credits\|points\|votes' --include='*.py' | grep -E '\+= |-= '

# SQLAlchemy: missing locking
grep -rn 'session\.query.*\.get(' --include='*.py' | grep -v 'with_for_update'

# Java/JPA: find unlocked reads before writes
grep -rn 'findById\|getOne\|getReference' --include='*.java' | grep -v 'Lock'

# Node/Mongoose: find-then-save pattern
grep -rn '\.findOne\|\.findById' --include='*.js' --include='*.ts' -A5 | grep '\.save()'

# Go: look for non-transactional multi-step operations
grep -rn 'func.*Handler\|func.*Service' --include='*.go' -A20 | grep -E 'Get.*Update|Find.*Save'

# General: find missing idempotency in payment/transfer endpoints
grep -rn 'payment\|transfer\|withdraw\|deposit\|purchase' --include='*.py' --include='*.js' --include='*.java' --include='*.go' | grep -iv 'idempoten'

# Find TOCTOU in file operations
grep -rn 'os\.path\.exists\|os\.access' --include='*.py' -A3 | grep 'open('
grep -rn 'os\.Stat' --include='*.go' -A5 | grep 'os\.Remove\|os\.Rename'
```

---

## Remediation Summary

| Technique | When to Use | Example |
|---|---|---|
| **Pessimistic lock** (`SELECT FOR UPDATE`) | High contention, critical correctness (financial) | `Account.objects.select_for_update().get(id=x)` |
| **Optimistic lock** (`@Version` / `WHERE version=N`) | Low contention, can retry on conflict | JPA `@Version`, Django `update()` with version check |
| **Atomic DB operations** | Simple increment/decrement | `F('balance') - amount`, `$inc`, `INCR` |
| **Unique constraints** | Prevent duplicate records | Unique index on `(user_id, coupon_code)` |
| **Idempotency keys** | API mutations (payments, orders) | `Idempotency-Key` header + dedup table |
| **Database transactions** | Multi-table consistency | `transaction.atomic()`, `BEGIN...COMMIT` |
| **Redis atomic scripts** | Rate limiting, distributed locks | Lua scripts with `EVAL` |
| **Application-level mutex** | Single-process only (not recommended for web) | `threading.Lock()`, `sync.Mutex` |
