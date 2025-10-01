from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL="postgresql+asyncpg://postgres:Pratikraj%40123@localhost:5432/practice"

engine = create_async_engine(url=DATABASE_URL, echo=True)

AsyncSessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine,class_=AsyncSession)

Base=declarative_base()

async def get_db():
    async with AsyncSessionLocal() as db:
        yield db
    

